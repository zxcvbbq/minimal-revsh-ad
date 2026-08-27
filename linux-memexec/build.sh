#!/bin/sh
set -eu

cc -O2 -s -Wall -Wextra -o memexec memexec.c -pthread
echo "built ./memexec"

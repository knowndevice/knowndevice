# SPDX-License-Identifier: Apache-2.0
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("secret_scan", ROOT / "scripts/secret_scan.py")
scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan)

# Built at runtime so this file does not trip the scanner or other secret detectors.
SAMPLES = {
    "pem-private-key": "-----BEGIN " + "EC PRIVATE KEY-----\nMHcCAQEE\n",
    "private-key-text": "loaded " + "PRIVATE KEY from slot\n",
    "der-private-key-base64": "key=" + "MIGHAgEAMBMGByqGSM49" + "AgEGCCqGSM49AwEHBG0wawIBAQQg\n",
    "jwk-private-member": '{"kty":"EC","d":"' + "A" * 43 + '"}\n',
    "github-token": "token=" + "ghp_" + "a1B2" * 9 + "\n",
    "aws-access-key-id": "key " + "AKIA" + "ABCDEFGHIJKLMNOP" + "\n",
    "slack-token": "xoxb-" + "123456789012-abc\n",
    "jwt": "ott " + "eyJhbGciOiJFUzI1NiJ9" + ".eyJzdWIiOiJkZXZpY2UifQ" + ".c2lnbmF0dXJlLXZhbHVl\n",
    "bearer-token": "Authorization: Bearer " + "x" * 32 + "\n",
}


class SecretScanTests(unittest.TestCase):
    def run_main(self, *paths):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = scan.main([str(path) for path in paths])
        return code, out.getvalue(), err.getvalue()

    def test_each_marker_blocks_and_only_its_name_is_printed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, text in SAMPLES.items():
                with self.subTest(marker=name):
                    path = root / f"{name}.log"
                    path.write_text("PASS cell\n" + text)
                    code, out, err = self.run_main(path)
                    self.assertEqual(code, 1)
                    self.assertIn(f"{path}: {name}", err)
                    for line in text.splitlines():
                        self.assertNotIn(line, out + err)
                    path.unlink()

    def test_unarmoured_der_keys_and_escaped_jwk_members_block(self):
        cases = {
            "sec1": "MHcCAQEE" + "IBYr4Y9nC0d8rKQ\n",
            "rsa-q": "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC" + "BKcwggSjAgEAAoIBAQ\n",
            "rsa-g": "MIIEvgIBADANBgkqhkiG9w0BAQEFAASC" + "BKgwggSkAgEAAoIBAQ\n",
            "escaped-jwk": '{"body":"{\\"kty\\":\\"EC\\",\\"d\\":\\"' + "B" * 43 + '\\"}"}\n',
        }
        with tempfile.TemporaryDirectory() as directory:
            for name, text in cases.items():
                with self.subTest(case=name):
                    path = Path(directory) / f"{name}.log"
                    path.write_text(text)
                    self.assertEqual(len(scan.problems([path])), 1)

    def test_unlistable_directory_and_special_files_block(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "logs/locked").mkdir(parents=True)
            os.mkfifo(root / "logs/pipe")
            (root / "logs/locked").chmod(0)
            try:
                if os.access(root / "logs/locked", os.R_OK):
                    self.skipTest("running with permissions that bypass directory modes")
                code, _, err = self.run_main(root / "logs")
            finally:
                (root / "logs/locked").chmod(0o700)
            self.assertEqual(code, 1)
            self.assertIn("locked: directory cannot be listed", err)
            self.assertIn("pipe: not a regular file", err)

    def test_file_option_requires_a_regular_file_and_skips_a_missing_one(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "logs").mkdir()
            (root / "logs/a.log").write_text("PASS\n")
            code, out, _ = self.run_main(root / "logs", "--file", root / "summary.txt")
            self.assertEqual(code, 0)
            self.assertIn("summary.txt does not exist; skipped", out)
            (root / "summary.txt").mkdir()
            (root / "summary.txt/inner.log").write_text("PASS\n")
            code, _, err = self.run_main(root / "logs", "--file", root / "summary.txt")
            self.assertEqual(code, 1)
            self.assertIn("summary.txt: not a regular file", err)
            (root / "summary.txt/inner.log").unlink()
            (root / "summary.txt").rmdir()
            os.symlink(root / "logs/a.log", root / "summary.txt")
            self.assertEqual(self.run_main(root / "logs", "--file", root / "summary.txt")[0], 1)

    def test_clean_logs_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "logs/nested").mkdir(parents=True)
            (root / "logs/cell-checks.log").write_text("PASS rotation\npublic key fingerprint sha256:abcd\nBearer of bad news\n")
            (root / "logs/nested/raw.bin").write_bytes(bytes(range(256)))
            (root / "summary.txt").write_text("commit: abc\nPASS generated-ci\n")
            code, out, _ = self.run_main(root / "logs", root / "summary.txt")
            self.assertEqual(code, 0)
            self.assertIn("no secret markers", out)

    def test_marker_in_a_nested_file_blocks_the_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "logs/deep").mkdir(parents=True)
            (root / "logs/ok.log").write_text("PASS\n")
            (root / "logs/deep/services.log").write_text(SAMPLES["pem-private-key"])
            code, _, err = self.run_main(root / "logs")
            self.assertEqual(code, 1)
            self.assertIn("deep/services.log: pem-private-key", err)
            self.assertNotIn("ok.log", err)

    def test_symbolic_links_are_blocked_not_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "keys").mkdir()
            (root / "keys/device.key").write_text("not scanned through the link\n")
            (root / "logs").mkdir()
            os.symlink(root / "keys/device.key", root / "logs/device.log")
            os.symlink(root / "keys", root / "logs/keys")
            code, _, err = self.run_main(root / "logs")
            self.assertEqual(code, 1)
            self.assertIn("device.log: symbolic link", err)
            self.assertIn("logs/keys: symbolic link", err)

    def test_missing_path_is_a_usage_error(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(self.run_main(Path(directory) / "absent")[0], 2)


if __name__ == "__main__":
    unittest.main()

# SPDX-License-Identifier: Apache-2.0
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("dco_check", ROOT / "scripts/dco_check.py")
dco = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dco)

GIT_ENV = {
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_AUTHOR_NAME": "Ada Example",
    "GIT_AUTHOR_EMAIL": "ada@example.invalid",
    "GIT_COMMITTER_NAME": "Ada Example",
    "GIT_COMMITTER_EMAIL": "ada@example.invalid",
}
SIGNED = "\n\nSigned-off-by: Ada Example <ada@example.invalid>\n"


class DcoCheckTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.repo = Path(self.directory.name)
        cleared = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_COMMON_DIR")
        self.saved_env = {key: os.environ.get(key) for key in (*GIT_ENV, *cleared)}
        for key in cleared:
            os.environ.pop(key, None)
        os.environ.update(GIT_ENV)
        self.git("init", "-q", "-b", "main")
        self.commit("base" + SIGNED)
        self.base = self.git("rev-parse", "HEAD")

    def tearDown(self):
        for key, value in self.saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self.directory.cleanup()

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.repo), "-c", "commit.gpgsign=false", *args], check=True, capture_output=True, text=True).stdout.strip()

    def commit(self, message):
        self.git("commit", "-q", "--allow-empty", "-m", message)
        return self.git("rev-parse", "HEAD")

    def check(self, head="HEAD"):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = dco.main(["--repo", str(self.repo), "--base", self.base, "--head", head])
        return code, out.getvalue(), err.getvalue()

    def test_signed_commits_pass(self):
        self.commit("feat: one" + SIGNED)
        self.commit("fix: two\n\nBody text.\n\nSigned-off-by: Bo Example <bo@example.invalid>\nReviewed-by: Cy <cy@example.invalid>\n")
        code, out, _ = self.check()
        self.assertEqual(code, 0)
        self.assertIn("2 non-merge commit(s)", out)

    def test_one_unsigned_commit_fails_and_is_named(self):
        self.commit("feat: signed" + SIGNED)
        sha = self.commit("fix: forgot the sign-off")
        code, _, err = self.check()
        self.assertEqual(code, 1)
        self.assertIn(f"{sha[:12]} fix: forgot the sign-off", err)
        self.assertNotIn("feat: signed", err)

    def test_sign_off_outside_the_trailer_block_or_without_email_fails(self):
        self.commit("fix: mid body\n\nSigned-off-by: Ada Example <ada@example.invalid>\n\nMore text after it.\n")
        self.commit("fix: no email\n\nSigned-off-by: Ada Example\n")
        self.commit("fix: empty\n\nSigned-off-by: \n")
        code, _, err = self.check()
        self.assertEqual(code, 1)
        self.assertIn("3 of 3 commit(s)", err)

    def test_merge_commits_are_skipped(self):
        self.git("checkout", "-q", "-b", "topic")
        self.commit("feat: topic" + SIGNED)
        self.git("checkout", "-q", "main")
        self.commit("chore: main moves" + SIGNED)
        self.git("merge", "-q", "--no-ff", "--no-edit", "topic")
        code, out, _ = self.check()
        self.assertEqual(code, 0)
        self.assertIn("2 non-merge commit(s)", out)

    def test_commits_already_in_base_are_not_checked(self):
        self.base = self.commit("old unsigned commit on the base branch")
        self.commit("feat: new" + SIGNED)
        self.assertEqual(self.check()[0], 0)

    def test_empty_range_passes(self):
        code, out, _ = self.check(self.base)
        self.assertEqual(code, 0)
        self.assertIn("0 non-merge commit(s)", out)

    def test_unknown_revision_is_an_error(self):
        code, _, err = self.check("0" * 40)
        self.assertEqual(code, 2)
        self.assertIn("cannot read", err)
        with self.assertRaisesRegex(dco.GitError, "must not start"):
            dco.commits(self.repo, "--output=/dev/null", "HEAD")

    def test_lowercase_trailer_key_counts(self):
        self.commit("fix: lower\n\nsigned-off-by: Ada Example <ada@example.invalid>\n")
        self.assertEqual(self.check()[0], 0)

    def test_merge_only_range_passes(self):
        self.git("checkout", "-q", "-b", "topic")
        topic = self.commit("feat: topic" + SIGNED)
        self.git("checkout", "-q", "main")
        self.git("merge", "-q", "--no-ff", "--no-edit", "topic")
        self.base = topic
        code, out, _ = self.check()
        self.assertEqual(code, 0)
        self.assertIn("0 non-merge commit(s)", out)

    def commit_bytes(self, message):
        path = Path(self.directory.name, "message.txt")
        path.write_bytes(message)
        self.git("-c", "i18n.commitEncoding=latin-1", "commit", "-q", "--allow-empty", "--cleanup=verbatim", "-F", str(path))
        path.unlink()
        return self.git("rev-parse", "HEAD")

    def test_control_and_non_utf8_bytes_are_handled(self):
        self.commit_bytes(b"fix: tab\x1f unit sep\x1e record sep" + SIGNED.encode())
        sha = self.commit_bytes(b"fix: caf\xe9 \x1b[31m::error::injected\x07\n")
        code, _, err = self.check()
        self.assertEqual(code, 1)
        self.assertIn("1 of 2 commit(s)", err)
        self.assertIn(sha[:12], err)
        self.assertNotIn("\x1b", err)
        self.assertNotIn("\x07", err)

    def test_malformed_git_output_is_an_error(self):
        for stdout in (b"not-a-sha\0\0subject\0", b"a" * 40 + b"\0trailers\0"):
            with self.subTest(stdout=stdout):
                fake = subprocess.CompletedProcess([], 0, stdout=stdout, stderr=b"")
                with mock.patch.object(dco.subprocess, "run", return_value=fake):
                    self.assertEqual(self.check()[0], 2)


if __name__ == "__main__":
    unittest.main()

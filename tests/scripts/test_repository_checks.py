# SPDX-License-Identifier: Apache-2.0
import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("checks", ROOT / "scripts/check_repository.py")
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)


class RepositoryCheckTests(unittest.TestCase):
    def copy_fixture(self, directory):
        root = Path(directory) / "fixture"
        shutil.copytree(ROOT, root, ignore=shutil.ignore_patterns(*checks.EXCLUDED))
        return root

    def test_detects_broken_link(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_fixture(directory)
            (root / "README.md").write_text("[missing](docs/absent.md)\n")
            self.assertTrue(any("missing link target" in error for error in checks.check(root)))

    @unittest.skipUnless((ROOT / "docs/ops/catalogue.json").exists(), "Internal operation catalogue is not published")
    def test_detects_uncatalogued_script(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_fixture(directory)
            (root / "scripts/uncatalogued.py").write_text("pass\n")
            self.assertIn("operation catalogue differs from scripts on disk", checks.check(root))

    def test_detects_broken_metadata_and_rule_glob(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_fixture(directory)
            (root / ".claude/rules").mkdir(parents=True, exist_ok=True)
            (root / ".claude/rules/continuity.md").write_text('---\npaths: ["absent/**/*.go"]\n---\nRule.\n')
            errors = checks.check(root)
            self.assertTrue(any("matches no file" in error for error in errors))
            (root / ".claude/rules/continuity.md").write_text('---\npaths: [broken\n---\nRule.\n')
            self.assertTrue(any("continuity.md" in error for error in checks.check(root)))

    def test_publication_fails_without_real_contacts(self):
        errors = checks.check(ROOT, publication=True)
        self.assertTrue(any("publication prerequisite missing" in error for error in errors))

    def test_public_checkout_does_not_require_internal_setup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("README.md", "LICENSE", "NOTICE", "CONTRIBUTING.md", "GOVERNANCE.md", "SECURITY.md", "CODE_OF_CONDUCT.md", "CHANGELOG.md", "ROADMAP.md"):
                (root / name).write_text("Public document.\n")
            self.assertEqual(checks.check(root), [])
            (root / "README.md").unlink()
            self.assertIn("missing README.md", checks.check(root))

    def test_partial_internal_setup_still_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "AGENTS.md").write_text("Local instructions.\n")
            errors = checks.check(root)
            self.assertIn("missing CLAUDE.md", errors)
            self.assertIn("missing operation catalogue", errors)


if __name__ == "__main__":
    unittest.main()

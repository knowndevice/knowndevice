# SPDX-License-Identifier: Apache-2.0
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("license_check", ROOT / "scripts/license_check.py")
license_check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(license_check)

LICENSES = "third_party/licenses"
ROOT_GO_MOD = """module example.test/project

go 1.27.0

require example.test/direct v1.2.3

require (
\texample.test/indirect v0.1.0 // indirect
)
"""
SDK_GO_MOD = """module example.test/consumer

go 1.27.0

require example.test/project v0.0.0

require example.test/indirect v0.1.0 // indirect

replace example.test/project => ../..
"""
STDLIB = ("go", "go1.27.3")
COVERED = [("example.test/direct", "v1.2.3"), ("example.test/indirect", "v0.1.0")]


def manifest_entry(module, version, name, data):
    if module == "go":
        identity = {"component": "Go standard library and runtime"}
        archive = f"https://go.dev/dl/{version}.src.tar.gz"
    else:
        identity = {"module": module}
        archive = f"https://proxy.golang.org/{module}/@v/{version}.zip"
    return {**identity, "version": version, "upstreamFile": name, "file": f"{module}@{version}/{name}", "sourceArchive": archive, "sha256": hashlib.sha256(data).hexdigest()}


class Fixture:
    """A small consistent repository whose coverage each test then damages."""

    def __init__(self, root):
        self.root = root
        self.licenses = root / LICENSES
        self.licenses.mkdir(parents=True)
        self.entries = []
        self.notice_lines = []
        self.rows = []
        self.write("go.mod", ROOT_GO_MOD)
        self.write("examples/sdk-consumer/go.mod", SDK_GO_MOD)
        self.write(".go-version", "1.27.3\n")
        for pair in COVERED:
            self.cover(*pair)
        self.cover(*STDLIB)
        self.save()

    def write(self, rel, text):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def cover(self, module, version, name="LICENSE", text="license text\n"):
        self.write(f"{LICENSES}/{module}@{version}/{name}", text)
        self.entries.append(manifest_entry(module, version, name, text.encode()))
        link = f"[{name}]({module}@{version}/{name})"
        if module == "go":
            self.notice_lines.append(f"Go standard library and runtime {version} - BSD-3-Clause")
            self.rows.append(f"| Go standard library and runtime | `{version}` | BSD-3-Clause | {link} |")
        else:
            self.notice_lines.append(f"{module} {version} - MIT")
            self.rows.append(f"| `{module}` | `{version}` | MIT | {link} |")

    def save(self, count=None):
        modules = len({entry["module"] for entry in self.entries if "module" in entry}) if count is None else count
        self.write("NOTICE", "Known Device\n\nThird-party software\n\n" + "\n".join(self.notice_lines) + "\n\nProse naming go.yaml.in/yaml v3 is not an entry.\n")
        table = "\n".join(["| Module | Pinned version | License | Copied files |", "| --- | --- | --- | --- |", *self.rows])
        self.write(f"{LICENSES}/README.md", f"# Third-party licenses\n\nFiles for the {modules} Go\nmodule versions.\n\n{table}\n")
        self.write(f"{LICENSES}/manifest.json", json.dumps({"schemaVersion": 1, "files": self.entries}))

    def replace(self, rel, old, new):
        path = self.root / rel
        text = path.read_text()
        if old not in text:
            raise AssertionError(f"{old!r} is not in {rel}")
        path.write_text(text.replace(old, new))


class LicenseCheckTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.fixture = Fixture(Path(directory.name))

    def errors(self):
        return license_check.check(self.fixture.root)

    def test_consistent_tree_passes(self):
        self.assertEqual(self.errors(), [])

    def test_missing_notice_line_names_the_module_version(self):
        self.fixture.replace("NOTICE", "example.test/indirect v0.1.0 - MIT\n", "")
        self.assertEqual(self.errors(), ["missing NOTICE line: example.test/indirect v0.1.0"])

    def test_notice_line_for_another_version_does_not_cover(self):
        self.fixture.replace("NOTICE", "example.test/direct v1.2.3 - MIT", "example.test/direct v1.2.4 - MIT")
        self.assertEqual(self.errors(), ["missing NOTICE line: example.test/direct v1.2.3", "stale NOTICE line: example.test/direct v1.2.4"])

    def test_missing_readme_row_names_the_module_version(self):
        self.fixture.replace(f"{LICENSES}/README.md", "| `example.test/direct` | `v1.2.3` | MIT | [LICENSE](example.test/direct@v1.2.3/LICENSE) |\n", "")
        self.assertEqual(self.errors(), ["missing README row: example.test/direct v1.2.3"])

    def test_missing_directory_names_the_path_and_its_manifest_entry(self):
        license_file = self.fixture.licenses / "example.test/direct@v1.2.3/LICENSE"
        license_file.unlink()
        license_file.parent.rmdir()
        self.assertEqual(self.errors(), ["missing license directory: third_party/licenses/example.test/direct@v1.2.3/", "manifest entry without a file: example.test/direct@v1.2.3/LICENSE"])

    def test_empty_directory_does_not_cover(self):
        (self.fixture.licenses / "example.test/direct@v1.2.3/LICENSE").unlink()
        self.assertIn("empty license directory: third_party/licenses/example.test/direct@v1.2.3/", self.errors())

    def test_digest_mismatch_names_the_file(self):
        self.fixture.write(f"{LICENSES}/example.test/direct@v1.2.3/LICENSE", "edited text\n")
        errors = self.errors()
        self.assertEqual(len(errors), 1)
        self.assertTrue(errors[0].startswith("digest mismatch: example.test/direct@v1.2.3/LICENSE: manifest "), errors[0])

    def test_copied_file_without_manifest_entry_fails(self):
        self.fixture.write(f"{LICENSES}/example.test/direct@v1.2.3/COPYING", "more text\n")
        errors = self.errors()
        self.assertIn("missing manifest entry: example.test/direct@v1.2.3/COPYING", errors)
        self.assertIn("README row does not link copied file: example.test/direct@v1.2.3/COPYING", errors)

    def test_manifest_entry_must_match_its_file_and_archive(self):
        entry = self.fixture.entries[0]
        self.fixture.entries[0] = {**entry, "upstreamFile": "COPYING", "sourceArchive": "https://example.test/archive.zip"}
        self.fixture.save()
        self.assertEqual(self.errors(), [
            "manifest entry names the wrong file: example.test/direct v1.2.3: file example.test/direct@v1.2.3/LICENSE, upstreamFile COPYING",
            "missing manifest entry: example.test/direct@v1.2.3/LICENSE",
        ])
        self.fixture.entries[0] = {**entry, "sourceArchive": "https://example.test/archive.zip"}
        self.fixture.save()
        self.assertEqual(self.errors(), ["wrong manifest sourceArchive: example.test/direct@v1.2.3/LICENSE: https://example.test/archive.zip"])

    def test_stale_coverage_after_a_version_bump_is_named(self):
        self.fixture.replace("go.mod", "example.test/direct v1.2.3", "example.test/direct v1.3.0")
        errors = self.errors()
        for expected in (
            "missing NOTICE line: example.test/direct v1.3.0",
            "missing README row: example.test/direct v1.3.0",
            "missing license directory: third_party/licenses/example.test/direct@v1.3.0/",
            "stale NOTICE line: example.test/direct v1.2.3",
            "stale README row: example.test/direct v1.2.3",
            "stale license directory: third_party/licenses/example.test/direct@v1.2.3/",
            "stale manifest entry: example.test/direct@v1.2.3/LICENSE",
        ):
            self.assertIn(expected, errors)

    def test_stale_coverage_alone_fails(self):
        self.fixture.cover("example.test/removed", "v9.0.0")
        self.fixture.save(count=2)
        self.assertEqual(self.errors(), [
            "stale NOTICE line: example.test/removed v9.0.0",
            "stale README row: example.test/removed v9.0.0",
            "stale license directory: third_party/licenses/example.test/removed@v9.0.0/",
            "stale manifest entry: example.test/removed@v9.0.0/LICENSE",
        ])

    def test_module_only_in_sdk_consumer_go_mod_requires_coverage(self):
        self.fixture.replace("examples/sdk-consumer/go.mod", "example.test/indirect v0.1.0 // indirect", "example.test/indirect v0.1.0 // indirect\nrequire example.test/consumer-only v2.0.0 // indirect")
        errors = self.errors()
        for expected in (
            "missing NOTICE line: example.test/consumer-only v2.0.0",
            "missing README row: example.test/consumer-only v2.0.0",
            "missing license directory: third_party/licenses/example.test/consumer-only@v2.0.0/",
        ):
            self.assertIn(expected, errors)
        self.fixture.cover("example.test/consumer-only", "v2.0.0")
        self.fixture.save()
        self.assertEqual(self.errors(), [])

    def test_two_versions_of_one_module_each_need_coverage(self):
        self.fixture.replace("examples/sdk-consumer/go.mod", "example.test/indirect v0.1.0 // indirect", "example.test/indirect v0.2.0 // indirect")
        errors = self.errors()
        self.assertIn("missing NOTICE line: example.test/indirect v0.2.0", errors)
        self.assertNotIn("stale NOTICE line: example.test/indirect v0.1.0", errors)

    def test_indirect_module_in_a_block_requires_coverage(self):
        self.fixture.replace("go.mod", "example.test/indirect v0.1.0 // indirect", "example.test/indirect v0.1.0 // indirect\n\texample.test/block v0.0.1 // indirect")
        self.assertIn("missing NOTICE line: example.test/block v0.0.1", self.errors())

    def test_local_replace_target_needs_no_coverage_but_a_required_copy_does(self):
        self.assertEqual(self.errors(), [])
        self.fixture.replace("examples/sdk-consumer/go.mod", "replace example.test/project => ../..", "replace example.test/project v0.0.1 => ../..")
        self.assertIn("missing NOTICE line: example.test/project v0.0.0", self.errors())

    def test_replace_to_another_module_fails_closed(self):
        self.fixture.replace("go.mod", "go 1.27.0", "go 1.27.0\n\nreplace example.test/direct => example.test/fork v1.2.3")
        self.assertIn("go.mod: replace to a module is not supported: replace example.test/direct => example.test/fork v1.2.3", self.errors())

    def test_missing_go_mod_fails(self):
        (self.fixture.root / "examples/sdk-consumer/go.mod").unlink()
        self.assertTrue(any(error.startswith("cannot read examples/sdk-consumer/go.mod") for error in self.errors()))

    def test_go_version_change_moves_the_standard_library_entry(self):
        self.fixture.write(".go-version", "1.27.4\n")
        errors = self.errors()
        for expected in (
            "missing NOTICE line: Go standard library and runtime go1.27.4",
            "stale NOTICE line: Go standard library and runtime go1.27.3",
            "missing README row: Go standard library and runtime go1.27.4",
            "stale README row: Go standard library and runtime go1.27.3",
            "missing license directory: third_party/licenses/go@go1.27.4/",
            "stale license directory: third_party/licenses/go@go1.27.3/",
            "stale manifest entry: go@go1.27.3/LICENSE",
        ):
            self.assertIn(expected, errors)

    def test_stale_go_version_in_prose_fails(self):
        self.fixture.replace(f"{LICENSES}/README.md", "# Third-party licenses", "# Third-party licenses for go1.26.0")
        self.assertEqual(self.errors(), ["stale Go version in README: go1.26.0"])

    def test_module_count_must_match(self):
        self.fixture.save(count=7)
        self.assertEqual(self.errors(), ["README module count: expected the 2 Go module versions, found the 7 Go module versions"])

    def test_stray_license_file_fails(self):
        self.fixture.write(f"{LICENSES}/example.test/LICENSE", "text\n")
        self.assertEqual(self.errors(), ["license file outside a module version directory: third_party/licenses/example.test/LICENSE"])

    def test_upstream_notice_must_be_reproduced_in_the_project_notice(self):
        text = "Upstream notice text.\n"
        self.fixture.write(f"{LICENSES}/example.test/direct@v1.2.3/NOTICE", text)
        self.fixture.entries.append(manifest_entry("example.test/direct", "v1.2.3", "NOTICE", text.encode()))
        self.fixture.rows[0] = "| `example.test/direct` | `v1.2.3` | MIT | [LICENSE](example.test/direct@v1.2.3/LICENSE), [NOTICE](example.test/direct@v1.2.3/NOTICE) |"
        self.fixture.save()
        self.assertEqual(self.errors(), ["project NOTICE does not reproduce third_party/licenses/example.test/direct@v1.2.3/NOTICE"])
        self.fixture.write("NOTICE", (self.fixture.root / "NOTICE").read_text() + "\n" + text)
        self.assertEqual(self.errors(), [])

    def test_main_prints_names_and_exits_non_zero(self):
        self.fixture.replace("NOTICE", "example.test/direct v1.2.3 - MIT\n", "")
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.assertEqual(license_check.main(self.fixture.root), 1)
        self.assertIn("missing NOTICE line: example.test/direct v1.2.3", stderr.getvalue())

    def test_main_exits_zero_on_a_consistent_tree(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(license_check.main(self.fixture.root), 0)


if __name__ == "__main__":
    unittest.main()

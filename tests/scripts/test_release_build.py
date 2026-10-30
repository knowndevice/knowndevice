# SPDX-License-Identifier: Apache-2.0
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("release_build", ROOT / "scripts/release_build.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)

COMMIT = "d7d16fd1d68f6b7a3df1aed97a9ad79aa6f338b6"


def build_info(**settings):
    values = {"-trimpath": "true", "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "arm64", "vcs.revision": COMMIT, "vcs.modified": "false"}
    values.update(settings)
    return {
        "GoVersion": "go1.27.3",
        "Path": "github.com/knowndevice/knowndevice/cmd/knowndevice",
        "Main": {"Path": "github.com/knowndevice/knowndevice", "Version": "v0.1.0"},
        "Deps": [
            {"Path": "github.com/spf13/cobra", "Version": "v1.10.2", "Sum": "h1:abc="},
            {"Path": "example.com/old", "Version": "v2.0.0+incompatible", "Replace": {"Path": "example.com/fork", "Version": "v2.1.0+incompatible"}},
        ],
        "Settings": [{"Key": key, "Value": value} for key, value in values.items()],
    }


class ReleaseBuildTests(unittest.TestCase):
    def test_versions(self):
        for version in ("0.1.0", "1.20.3", "0.1.0-rc.1", release.DEV_VERSION):
            release.check_version(version)
        for version in ("v0.1.0", "0.1", "01.2.3", "0.1.0+build", "0.1.0-", ""):
            with self.assertRaises(release.ReleaseError, msg=version):
                release.check_version(version)

    def test_build_info_must_match_clean_pinned_target(self):
        release.check_build(build_info(), "arm64", COMMIT, "go1.27.3")
        for settings, arch, toolchain in (({"vcs.modified": "true"}, "arm64", "go1.27.3"), ({"vcs.revision": "0" * 40}, "arm64", "go1.27.3"), ({}, "amd64", "go1.27.3"), ({"CGO_ENABLED": "1"}, "arm64", "go1.27.3"), ({}, "arm64", "go1.27.2")):
            with self.assertRaises(release.ReleaseError):
                release.check_build(build_info(**settings), arch, COMMIT, toolchain)
        release.check_build(build_info(), "arm64", COMMIT, "go1.27.3", "v0.1.0")
        with self.assertRaisesRegex(release.ReleaseError, "empty GOMODCACHE"):
            release.check_build(build_info(), "arm64", COMMIT, "go1.27.3", "v0.1.1")

    def test_archive_is_byte_identical_and_normalized(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "tool"
            source.write_bytes(b"binary")
            source.chmod(0o700)
            items = [("pkg/bin/tool", source, 0o755), ("pkg/LICENSE", b"text", 0o644)]
            first, second = Path(directory) / "a.tar.gz", Path(directory) / "b.tar.gz"
            release.write_archive(first, items, 1700000000)
            release.write_archive(second, list(reversed(items)), 1700000000)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with tarfile.open(first) as tar:
                members = tar.getmembers()
            self.assertEqual([m.name for m in members], ["pkg", "pkg/LICENSE", "pkg/bin", "pkg/bin/tool"])
            self.assertEqual({(m.uid, m.gid, m.uname, m.gname, m.mtime) for m in members}, {(0, 0, "", "", 1700000000)})
            self.assertEqual([oct(m.mode) for m in members], ["0o755", "0o644", "0o755", "0o755"])

    def test_sbom_lists_each_module_once_with_purls(self):
        binaries = [("knowndevice", "11" * 32, build_info()), ("kd-adapter", "22" * 32, build_info())]
        document = release.sbom("knowndevice_0.1.0_linux_arm64.tar.gz", "0.1.0", COMMIT, 1700000000, binaries)
        self.assertEqual(document, json.loads(json.dumps(document)))
        # actions/attest recognizes CycloneDX only when all three fields are present.
        self.assertTrue(document["bomFormat"] and document["specVersion"] and document["serialNumber"].startswith("urn:uuid:"))
        refs = [component["bom-ref"] for component in document["components"]]
        self.assertEqual(len(refs), len(set(refs)))
        self.assertIn("pkg:golang/stdlib@1.27.3", refs)
        self.assertIn("pkg:golang/example.com/fork@v2.1.0%2Bincompatible", refs)
        self.assertNotIn("pkg:golang/example.com/old@v2.0.0%2Bincompatible", refs)
        self.assertEqual(document["metadata"]["timestamp"], "2023-11-14T22:13:20Z")
        for dependency in document["dependencies"]:
            self.assertTrue({dependency["ref"], *dependency["dependsOn"]} <= set(refs) | {"knowndevice_0.1.0_linux_arm64.tar.gz"})
        self.assertEqual(document, release.sbom("knowndevice_0.1.0_linux_arm64.tar.gz", "0.1.0", COMMIT, 1700000000, binaries))

    def test_checksums_cover_every_output_in_order(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            (out / "b.tar.gz").write_bytes(b"b")
            (out / "a.cdx.json").write_bytes(b"a")
            release.write_checksums(out)
            lines = (out / "SHA256SUMS").read_text().splitlines()
            self.assertEqual([line.split("  ")[1] for line in lines], ["a.cdx.json", "b.tar.gz"])
            self.assertEqual(lines[0].split("  ")[0], release.sha256(b"a"))

    def test_refuses_nonempty_output(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "stale").write_text("x")
            stderr = io.StringIO()
            with mock.patch("sys.stderr", stderr):
                self.assertEqual(release.main(["--version", "0.0.0-dev", "--out", directory]), 1)
            self.assertIn("is not empty", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()

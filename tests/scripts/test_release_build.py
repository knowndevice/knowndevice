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


def fake_run(status="", tags="", goversion="go1.27.3", fail_arch=None):
    def run(command, env=None):
        if command[:2] == ["git", "status"]:
            return status
        if command[:2] == ["git", "rev-parse"]:
            return COMMIT + "\n"
        if command[:2] == ["git", "log"]:
            return "1700000000\n"
        if command[:2] == ["git", "tag"]:
            return tags
        if command[:2] == ["git", "ls-files"]:
            return "third_party/licenses/README.md\0"
        if command[:2] == ["go", "env"]:
            return f"{goversion}\ndarwin\narm64\n"
        if command[:2] == ["go", "build"]:
            if env["GOARCH"] == fail_arch:
                raise release.ReleaseError("go build failed")
            binary = Path(command[command.index("-o") + 1])
            binary.parent.mkdir(parents=True, exist_ok=True)
            binary.write_bytes(env["GOARCH"].encode())
            return ""
        if command[:2] == ["go", "version"]:
            return json.dumps(build_info(GOARCH=Path(command[-1]).parent.name))
        raise AssertionError(command)
    return run


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

    def test_go_env_ignores_inherited_build_settings(self):
        inherited = {"GOFLAGS": "-tags=x", "GOAMD64": "v3", "GOEXPERIMENT": "y", "CGO_ENABLED": "1", "GOOS": "darwin", "GOMODCACHE": "/cache", "PATH": "/bin"}
        with mock.patch.dict("os.environ", inherited, clear=True):
            env = release.go_env("arm64")
        self.assertEqual({key: env.get(key) for key in ("GOFLAGS", "GOAMD64", "GOEXPERIMENT")}, dict.fromkeys(("GOFLAGS", "GOAMD64", "GOEXPERIMENT")))
        self.assertEqual((env["GOENV"], env["GOTOOLCHAIN"], env["CGO_ENABLED"], env["GOOS"], env["GOARCH"], env["GOMODCACHE"], env["PATH"]), ("off", "local", "0", "linux", "arm64", "/cache", "/bin"))

    def test_refuses_directory_replace_and_duplicate_members(self):
        info = build_info()
        info["Deps"].append({"Path": "example.com/local", "Version": "v1.0.0", "Replace": {"Path": "../local"}})
        with self.assertRaisesRegex(release.ReleaseError, "directory replace"):
            release.sbom("a.tar.gz", "0.1.0", COMMIT, 1700000000, [("knowndevice", "11" * 32, info)])
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(release.ReleaseError, "duplicate"):
            release.write_archive(Path(directory) / "a.tar.gz", [("p/x", b"1", 0o644), ("p/x", b"2", 0o644)], 1700000000)

    def test_complete_build_publishes_only_after_every_step(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(release, "run", fake_run()):
            out = Path(directory) / "out"
            release.release(release.DEV_VERSION, out)
            names = sorted(path.name for path in out.iterdir())
            self.assertEqual(names, ["SHA256SUMS", "knowndevice_0.0.0-dev_linux_amd64.cdx.json", "knowndevice_0.0.0-dev_linux_amd64.tar.gz", "knowndevice_0.0.0-dev_linux_arm64.cdx.json", "knowndevice_0.0.0-dev_linux_arm64.tar.gz"])
            self.assertEqual(len((out / "SHA256SUMS").read_text().splitlines()), 4)

    def test_refusals_write_nothing(self):
        cases = [
            (release.DEV_VERSION, {"status": "?? stray\n"}, "uncommitted"),
            (release.DEV_VERSION, {"goversion": "go1.27.2"}, "requires go1.27.3"),
            (release.DEV_VERSION, {"fail_arch": "arm64"}, "go build failed"),
            ("0.1.0", {"tags": "v0.1.0-rc.1\n"}, "does not point at HEAD"),
        ]
        for version, options, message in cases:
            with self.subTest(message), tempfile.TemporaryDirectory() as directory, mock.patch.object(release, "run", fake_run(**options)):
                out = Path(directory) / "out"
                with self.assertRaisesRegex(release.ReleaseError, message):
                    release.release(version, out)
                self.assertFalse(out.exists())

    def test_refuses_nonempty_output(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "stale").write_text("x")
            stderr = io.StringIO()
            with mock.patch("sys.stderr", stderr):
                self.assertEqual(release.main(["--version", "0.0.0-dev", "--out", directory]), 1)
            self.assertIn("is not an empty directory", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()

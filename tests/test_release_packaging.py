"""Portable archive contents, permissions, names and publication completeness."""
import hashlib
import importlib.util
from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile


spec = importlib.util.spec_from_file_location(
    "package_release", Path(__file__).resolve().parents[1] / "scripts/package-release.py"
)
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleasePackagingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="netcrow-package-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.output = self.root / "dist"
        (self.root / "examples").mkdir()
        for name in ("README.md", "LICENSE", "examples/relay.toml",
                     "examples/office.toml", "examples/home.toml",
                     "netcrow-client.service", "netcrow-relay.service"):
            (self.root / name).write_text(f"fixture for {name}\n", encoding="utf-8")
        # Files outside the explicit distribution list must never enter a release.
        (self.root / "private-key.pem").write_text("not for distribution", encoding="utf-8")
        for target in release.TARGETS:
            binary = self.root / "target" / target / "release" / (
                "netcrow.exe" if "windows" in target else "netcrow"
            )
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"test-binary\x00" + target.encode())

    def package_all(self, tag="v1.2.3"):
        return [release.package(self.root, target, tag, self.output) for target in release.TARGETS]

    def test_all_platform_archives_and_checksums(self):
        packages = self.package_all()
        for target, path in zip(release.TARGETS, packages):
            stem = f"netcrow-v1.2.3-{target}"
            binary_name = "netcrow.exe" if "windows" in target else "netcrow"
            expected = {f"{stem}/{name}" for name in (
                binary_name, "README.md", "LICENSE", "examples/relay.toml",
                "examples/office.toml", "examples/home.toml",
            )}
            if "linux" in target:
                expected.update(f"{stem}/{name}" for name in (
                    "netcrow-client.service", "netcrow-relay.service",
                ))
            if path.suffix == ".zip":
                with zipfile.ZipFile(path) as archive:
                    self.assertEqual(set(archive.namelist()), expected)
                    binary = archive.read(f"{stem}/{binary_name}")
            else:
                with tarfile.open(path) as archive:
                    self.assertEqual(set(archive.getnames()), expected)
                    self.assertEqual(archive.getmember(f"{stem}/{binary_name}").mode, 0o755)
                    binary = archive.extractfile(f"{stem}/{binary_name}").read()
            self.assertEqual(binary, b"test-binary\x00" + target.encode())
        manifest = release.checksum_assets(self.output).read_text(encoding="utf-8")
        self.assertEqual(len(manifest.splitlines()), 6)
        for line in manifest.splitlines():
            digest, name = line.split("  ")
            self.assertEqual(digest, hashlib.sha256((self.output / name).read_bytes()).hexdigest())
        # Re-running aggregation must ignore its own output and remain stable.
        self.assertEqual(release.checksum_assets(self.output).read_text(encoding="utf-8"), manifest)

    def test_missing_platform_or_mixed_versions_cannot_be_published(self):
        packages = self.package_all()
        packages[0].unlink()
        with self.assertRaisesRegex(ValueError, "expected 6"):
            release.checksum_assets(self.output)
        release.package(self.root, release.TARGETS[0], "v9.9.9", self.output)
        with self.assertRaisesRegex(ValueError, "different versions"):
            release.checksum_assets(self.output)

    def test_arbitrary_tag_cannot_escape_output_directory(self):
        for tag in ("release/v1", "../v1", "-v1", "版本1", "$(touch nope)", "v" * 300):
            path = release.package(self.root, release.TARGETS[0], tag, self.output)
            self.assertEqual(path.parent, self.output)
            self.assertLess(len(path.name), 200)
            with tarfile.open(path) as archive:
                for member in archive.getmembers():
                    self.assertNotIn("..", Path(member.name).parts)
                    self.assertFalse(Path(member.name).is_absolute())
        self.assertNotEqual(release.artifact_version("release/v1"), release.artifact_version("release_v1"))

    def test_missing_or_empty_binary_does_not_create_package(self):
        target = release.TARGETS[0]
        binary = self.root / "target" / target / "release/netcrow"
        binary.write_bytes(b"")
        with self.assertRaisesRegex(ValueError, "empty"):
            release.package(self.root, target, "v1", self.output)
        binary.unlink()
        with self.assertRaisesRegex(ValueError, "missing"):
            release.package(self.root, target, "v1", self.output)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()

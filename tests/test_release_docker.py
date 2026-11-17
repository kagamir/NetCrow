"""Validate image inputs, architecture/static-link checks and exact tag policy."""
import importlib.util
import io
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest


spec = importlib.util.spec_from_file_location(
    "prepare_docker", Path(__file__).resolve().parents[1] / "scripts/prepare-docker.py"
)
docker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(docker)


def elf(machine, kind=1):
    binary = bytearray(120)
    binary[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<H", binary, 18, machine)
    struct.pack_into("<Q", binary, 32, 64)
    struct.pack_into("<HH", binary, 54, 56, 1)
    struct.pack_into("<I", binary, 64, kind)
    return bytes(binary)


class DockerReleaseTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="netcrow-docker-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.archives = self.root / "dist"
        self.archives.mkdir()
        self.output = self.root / "docker-bin"

    def archive(self, target, *, tag="v1.2.3", binary=None, symlink=False):
        stem = f"netcrow-{docker.artifact_version(tag)}-{target}"
        path = self.archives / f"{stem}.tar.gz"
        if binary is None:
            binary = elf(docker.TARGETS[target][1])
        with tarfile.open(path, "w:gz") as archive:
            member = tarfile.TarInfo(f"{stem}/netcrow")
            if symlink:
                member.type = tarfile.SYMTYPE
                member.linkname = "../../outside"
                archive.addfile(member)
            else:
                member.size = len(binary)
                archive.addfile(member, io.BytesIO(binary))
            # Only the explicitly named executable is ever read, not extracted.
            unrelated = tarfile.TarInfo("../../not-an-image-file")
            unrelated.size = 6
            archive.addfile(unrelated, io.BytesIO(b"ignore"))
        return path

    def test_both_native_linux_binaries_are_staged_without_extracting_other_paths(self):
        for target in docker.TARGETS:
            self.archive(target)
        (self.archives / "netcrow-v1.2.3-x86_64-apple-darwin.tar.gz").write_bytes(b"ignored")
        self.assertEqual(docker.prepare(self.archives, self.output, require_all=True, tag="v1.2.3"),
                         ["amd64", "arm64"])
        for arch, machine in docker.TARGETS.values():
            binary = self.output / arch / "netcrow"
            self.assertEqual(binary.read_bytes(), elf(machine))
            self.assertEqual(binary.stat().st_mode & 0o777, 0o755)
        self.assertEqual({path.relative_to(self.output).as_posix()
                          for path in self.output.rglob("*") if path.is_file()},
                         {"amd64/netcrow", "arm64/netcrow"})
        self.assertFalse((self.root / "not-an-image-file").exists())

    def test_single_architecture_is_allowed_but_multiarch_requires_both(self):
        self.archive("x86_64-unknown-linux-musl")
        with self.assertRaisesRegex(ValueError, "amd64 and arm64"):
            docker.prepare(self.archives, self.output, require_all=True)
        self.assertFalse(self.output.exists())
        self.assertEqual(docker.prepare(self.archives, self.output), ["amd64"])

    def test_wrong_architecture_dynamic_binary_and_symlink_are_rejected(self):
        for options, error in (
            ({"binary": elf(183)}, "architecture"),
            ({"binary": elf(62, kind=3)}, "interpreter"),
            ({"binary": b"not a Linux executable"}, "ELF"),
            ({"symlink": True}, "regular executable"),
        ):
            with self.subTest(options=options):
                self.archive("x86_64-unknown-linux-musl", **options)
                with self.assertRaisesRegex(ValueError, error):
                    docker.prepare(self.archives, self.output)
                self.assertFalse(self.output.exists())

    def test_shared_library_dependency_is_rejected_even_without_interpreter(self):
        binary = bytearray(elf(62, kind=2))
        binary.extend(bytes(16))
        struct.pack_into("<Q", binary, 64 + 8, 120)
        struct.pack_into("<Q", binary, 64 + 32, 16)
        struct.pack_into("<q", binary, 120, 1)  # DT_NEEDED
        self.archive("x86_64-unknown-linux-musl", binary=bytes(binary))
        with self.assertRaisesRegex(ValueError, "shared-library dependency"):
            docker.prepare(self.archives, self.output)

    def test_mixed_or_mismatched_release_versions_cannot_be_tagged(self):
        self.archive("x86_64-unknown-linux-musl")
        self.archive("aarch64-unknown-linux-musl", tag="v2.0.0")
        with self.assertRaisesRegex(ValueError, "different versions"):
            docker.prepare(self.archives, self.output, require_all=True)
        with self.assertRaisesRegex(ValueError, "requested Git tag"):
            docker.prepare(self.archives, self.output, require_all=True, tag="v1.2.3")
        self.assertFalse(self.output.exists())

    def test_publish_references_are_only_exact_tag_and_latest(self):
        for tag in ("v1.2.3", "v2.0.0-rc.1", "Release_2026", "a" * 128):
            self.assertEqual(docker.image_tags(tag),
                             [f"ghcr.io/kagamir/netcrow:{tag}", "ghcr.io/kagamir/netcrow:latest"])
        self.assertEqual(docker.image_tags("latest"), ["ghcr.io/kagamir/netcrow:latest"])
        for tag in ("", "release/v1", "v1+build", "-v1", ".v1", "a" * 129,
                    "$(touch file)", "v1\nlatest", "版本1"):
            with self.subTest(tag=tag), self.assertRaisesRegex(ValueError, "valid Docker tag"):
                docker.image_tags(tag)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Prepare a Docker build context from tested Linux release archives.

Single-platform builds require its corresponding archive; use --require-all for
linux/amd64,linux/arm64. --tag validates an exact Docker tag and writes the only
permitted publish references (that tag and latest) to GITHUB_OUTPUT when set.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
from pathlib import Path
import re
import struct
import tarfile


IMAGE = "ghcr.io/kagamir/netcrow"
TARGETS = {
    "x86_64-unknown-linux-musl": ("amd64", 62),
    "aarch64-unknown-linux-musl": ("arm64", 183),
}
MAX_BINARY = 256 * 1024 * 1024


def image_tags(tag: str) -> list[str]:
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", tag, flags=re.ASCII):
        raise ValueError(
            "Git tag is not a valid Docker tag: use 1..128 ASCII letters, digits, "
            "underscores, periods or hyphens, starting with a letter, digit or underscore; "
            "the tag will not be silently renamed"
        )
    return list(dict.fromkeys((f"{IMAGE}:{tag}", f"{IMAGE}:latest")))


def artifact_version(tag: str) -> str:
    spec = importlib.util.spec_from_file_location(
        "netcrow_docker_packaging", Path(__file__).with_name("package-release.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.artifact_version(tag)


def static_elf(binary: bytes, machine: int) -> None:
    if len(binary) < 64 or binary[:6] != b"\x7fELF\x02\x01":
        raise ValueError("Docker binary must be a little-endian 64-bit Linux ELF")
    if struct.unpack_from("<H", binary, 18)[0] != machine:
        raise ValueError("Docker binary architecture does not match its release archive")
    offset = struct.unpack_from("<Q", binary, 32)[0]
    size, count = struct.unpack_from("<HH", binary, 54)
    if size < 56 or count == 0 or offset + size * count > len(binary):
        raise ValueError("Docker binary has an invalid ELF program-header table")
    for index in range(count):
        header = offset + index * size
        kind = struct.unpack_from("<I", binary, header)[0]
        if kind == 3:  # PT_INTERP requires a loader unavailable in scratch.
            raise ValueError("Docker binary must be static: ELF interpreter found")
        if kind == 2:  # PT_DYNAMIC may exist for static PIE, but DT_NEEDED may not.
            dynamic_offset = struct.unpack_from("<Q", binary, header + 8)[0]
            dynamic_size = struct.unpack_from("<Q", binary, header + 32)[0]
            if dynamic_size % 16 or dynamic_offset + dynamic_size > len(binary):
                raise ValueError("Docker binary has an invalid ELF dynamic table")
            for entry in range(dynamic_offset, dynamic_offset + dynamic_size, 16):
                dynamic_tag = struct.unpack_from("<q", binary, entry)[0]
                if dynamic_tag == 0:
                    break
                if dynamic_tag == 1:
                    raise ValueError("Docker binary must be static: shared-library dependency found")


def prepare(archives: Path, output: Path, *, require_all: bool = False,
            tag: str | None = None) -> list[str]:
    if tag is not None:
        image_tags(tag)
    if not archives.is_dir():
        raise ValueError(f"release archive directory does not exist: {archives}")
    found = {}
    versions = set()
    for path in sorted(archives.iterdir()):
        target = next((target for target in TARGETS
                       if path.name.endswith(f"-{target}.tar.gz")), None)
        if target is None:
            continue  # Other platforms and SHA256SUMS are not image inputs.
        arch, machine = TARGETS[target]
        if arch in found:
            raise ValueError(f"multiple Linux release archives for {arch}")
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"release archive is not a regular file: {path}")
        if not re.fullmatch(r"netcrow-[A-Za-z0-9._-]+", path.name):
            raise ValueError(f"unsafe release archive name: {path.name}")
        version = path.name[len("netcrow-"):-len(f"-{target}.tar.gz")]
        if not version or (tag is not None and version != artifact_version(tag)):
            raise ValueError("release archive does not match the requested Git tag")
        versions.add(version)
        member_name = f"{path.name[:-len('.tar.gz')]}/netcrow"
        with tarfile.open(path, "r:gz") as archive:
            matching = [member for member in archive.getmembers() if member.name == member_name]
            if len(matching) != 1 or not matching[0].isfile():
                raise ValueError(f"archive must contain one regular executable: {member_name}")
            if not 0 < matching[0].size <= MAX_BINARY:
                raise ValueError("release executable is empty or exceeds the binary size limit")
            with archive.extractfile(matching[0]) as stream:
                binary = stream.read(MAX_BINARY + 1)
            if len(binary) != matching[0].size:
                raise ValueError("truncated release executable")
        static_elf(binary, machine)
        found[arch] = binary
    if not found or (require_all and len(found) != len(TARGETS)):
        raise ValueError("supply Linux amd64 and arm64 archives" if require_all
                         else "no Linux release archive found")
    if len(versions) != 1:
        raise ValueError("Linux release archives have different versions")
    # Read only the exact executable member; never extract arbitrary archive paths.
    for arch, binary in found.items():
        destination = output / arch / "netcrow"
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(binary)
        destination.chmod(0o755)
    return sorted(found)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archives", type=Path, default=Path("dist"))
    parser.add_argument("--output", type=Path, default=Path("docker-bin"))
    parser.add_argument("--require-all", action="store_true")
    parser.add_argument("--tag")
    args = parser.parse_args()
    try:
        platforms = prepare(args.archives, args.output, require_all=args.require_all, tag=args.tag)
        print("Prepared " + ", ".join(f"linux/{arch}" for arch in platforms))
        if args.tag is not None:
            tags = ",".join(image_tags(args.tag))
            print(f"Publish references: {tags}")
            if output := os.environ.get("GITHUB_OUTPUT"):
                with open(output, "a", encoding="utf-8") as stream:
                    stream.write(f"tags={tags}\n")
    except (OSError, ValueError, tarfile.TarError) as error:
        parser.exit(1, f"Docker preparation failed: {error}\n")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Package native release binaries or validate the complete release asset set.

Uses only the Python standard library; run from the repository root.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
from pathlib import Path
import re
import tarfile
import zipfile


TARGETS = (
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-musl",
    "x86_64-pc-windows-msvc",
    "aarch64-pc-windows-msvc",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
)


def artifact_version(tag: str) -> str:
    """Keep normal version tags readable; safely encode other Git tag names."""
    if not tag:
        raise ValueError("tag must not be empty")
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", tag).strip("._-")[:96]
    if cleaned != tag:
        cleaned = f"{cleaned or 'tag'}-{hashlib.sha256(tag.encode()).hexdigest()[:12]}"
    return cleaned


def package(root: Path, target: str, tag: str, output: Path) -> Path:
    if target not in TARGETS:
        raise ValueError(f"unsupported target: {target}")
    windows = "windows" in target
    binary_name = "netcrow.exe" if windows else "netcrow"
    binary = root / "target" / target / "release" / binary_name
    files = [(binary, binary_name, 0o755)]
    files += [(root / name, name, 0o644) for name in ("README.md", "LICENSE")]
    files += [(root / "examples" / name, f"examples/{name}", 0o644)
              for name in ("relay.toml", "office.toml", "home.toml")]
    if "linux" in target:
        files += [(root / name, name, 0o644)
                  for name in ("netcrow-client.service", "netcrow-relay.service")]
    for path, _, _ in files:
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"required release file is missing or not a regular file: {path}")
    if binary.stat().st_size == 0:
        raise ValueError(f"release binary is empty: {binary}")

    stem = f"netcrow-{artifact_version(tag)}-{target}"
    output.mkdir(parents=True, exist_ok=True)
    destination = output / f"{stem}{'.zip' if windows else '.tar.gz'}"
    # A failed packaging attempt cannot leave a plausible final archive behind.
    temporary = destination.with_name(destination.name + ".tmp")
    try:
        if windows:
            with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for path, relative, mode in files:
                    member = zipfile.ZipInfo(f"{stem}/{relative}")
                    member.create_system = 3
                    member.external_attr = (0o100000 | mode) << 16
                    member.compress_type = zipfile.ZIP_DEFLATED
                    archive.writestr(member, path.read_bytes())
        else:
            with temporary.open("wb") as stream:
                with gzip.GzipFile(filename="", mode="wb", fileobj=stream, mtime=0) as compressed:
                    with tarfile.open(fileobj=compressed, mode="w|") as archive:
                        for path, relative, mode in files:
                            member = tarfile.TarInfo(f"{stem}/{relative}")
                            member.mode = mode
                            member.size = path.stat().st_size
                            with path.open("rb") as contents:
                                archive.addfile(member, contents)
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)
    return destination


def checksum_assets(directory: Path) -> Path:
    """Require one package for every platform, all from the same version."""
    if not directory.is_dir():
        raise ValueError(f"asset directory does not exist: {directory}")
    files = sorted(path for path in directory.iterdir() if path.name != "SHA256SUMS")
    if len(files) != len(TARGETS):
        raise ValueError(f"expected {len(TARGETS)} release packages, found {len(files)}")
    seen = set()
    versions = set()
    lines = []
    for path in files:
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"invalid release asset: {path}")
        if not re.fullmatch(r"netcrow-[A-Za-z0-9._-]+", path.name):
            raise ValueError(f"unsafe release asset name: {path.name}")
        target = next((candidate for candidate in TARGETS
                       if path.name.endswith(f"-{candidate}{'.zip' if 'windows' in candidate else '.tar.gz'}")), None)
        if target is None or target in seen:
            raise ValueError(f"unexpected or duplicate release platform: {path.name}")
        seen.add(target)
        extension = ".zip" if "windows" in target else ".tar.gz"
        version = path.name[len("netcrow-"):-len(f"-{target}{extension}")]
        if not version:
            raise ValueError(f"missing release version: {path.name}")
        versions.add(version)
        if path.stat().st_size == 0:
            raise ValueError(f"release asset is empty: {path.name}")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        lines.append(f"{digest.hexdigest()}  {path.name}\n")
    if len(versions) != 1:
        raise ValueError("release packages have different versions")
    result = directory / "SHA256SUMS"
    result.write_text("".join(lines), encoding="utf-8", newline="\n")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=TARGETS)
    parser.add_argument("--tag")
    parser.add_argument("--output", type=Path, default=Path("dist"))
    parser.add_argument("--checksums", type=Path, metavar="ASSET_DIRECTORY")
    args = parser.parse_args()
    if args.checksums is not None:
        if args.target or args.tag:
            parser.error("--checksums cannot be combined with --target or --tag")
        result = checksum_assets(args.checksums)
    else:
        if not args.target or not args.tag:
            parser.error("packaging requires --target and --tag")
        result = package(Path.cwd(), args.target, args.tag, args.output)
    print(result)


if __name__ == "__main__":
    main()

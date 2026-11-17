#!/usr/bin/env python3
"""Publish complete NetCrow release assets without overwriting published files.

Uses the authenticated GitHub CLI. New releases remain drafts until verified;
published empty or partial releases receive only missing assets.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from urllib.parse import quote


class PublishError(RuntimeError):
    """A release cannot be completed safely."""


def gh(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["gh", *args], capture_output=True, text=True, check=False)


def checked(*args: str) -> str:
    result = gh(*args)
    if result.returncode:
        raise PublishError(result.stderr.strip() or result.stdout.strip() or "GitHub CLI failed")
    return result.stdout


def metadata(repo: str, tag: str) -> dict | None:
    result = gh("api", f"repos/{repo}/releases/tags/{quote(tag, safe='')}")
    if result.returncode:
        if not re.search(r"\bHTTP 404\b", result.stderr):
            raise PublishError(result.stderr.strip() or "Could not look up the release")
        # REST's tag endpoint cannot find a draft by its pending tag. The CLI
        # combines that endpoint with GraphQL draft discovery; fetch its ID so
        # both published and draft releases retain the same REST metadata shape.
        found = gh("release", "view", "--repo", repo,
                   "--json", "databaseId", "--jq", ".databaseId", "--", tag)
        if found.returncode:
            if found.stderr.strip().lower() == "release not found":
                return None
            raise PublishError(found.stderr.strip() or "Could not look up draft releases")
        release_id = found.stdout.strip()
        if not re.fullmatch(r"[1-9][0-9]*", release_id):
            raise PublishError("GitHub returned an invalid release ID")
        result = gh("api", f"repos/{repo}/releases/{release_id}")
        if result.returncode:
            raise PublishError(result.stderr.strip() or "Could not fetch the release by ID")
    try:
        release = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise PublishError("GitHub returned invalid release metadata") from error
    if not isinstance(release, dict) or not isinstance(release.get("draft"), bool):
        raise PublishError("GitHub returned incomplete release metadata")
    return release


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as contents:
        for block in iter(lambda: contents.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def packaging_module():
    path = Path(__file__).with_name("package-release.py")
    spec = importlib.util.spec_from_file_location("netcrow_release_packaging", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def parse_manifest(path: Path, expected_names: set[str]) -> dict[str, str]:
    hashes = {}
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            match = re.fullmatch(r"([0-9a-fA-F]{64})  ([A-Za-z0-9._-]+)", line)
            if not match:
                raise PublishError("Release SHA256SUMS has an invalid entry")
            checksum, name = match.groups()
            if name not in expected_names or name in hashes:
                raise PublishError("Release SHA256SUMS has an unexpected or duplicate asset")
            hashes[name] = checksum.lower()
    except (OSError, UnicodeError) as error:
        raise PublishError("Could not read release SHA256SUMS") from error
    if hashes.keys() != expected_names:
        raise PublishError("Release SHA256SUMS does not describe all six packages")
    return hashes


def write_manifest(path: Path, hashes: dict[str, str]) -> None:
    path.write_text("".join(f"{hashes[name]}  {name}\n" for name in sorted(hashes)),
                    encoding="utf-8", newline="\n")


def assets_by_name(release: dict) -> dict[str, dict]:
    assets = {}
    for asset in release.get("assets", []):
        name = asset.get("name")
        if not isinstance(name, str) or name in assets:
            raise PublishError("GitHub returned invalid or duplicate release assets")
        assets[name] = asset
    return assets


def download(tag: str, names: list[str], destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    if not names:
        return
    args = ["release", "download", "--dir", str(destination)]
    for name in names:
        args.extend(["--pattern", name])
    checked(*args, "--", tag)
    for name in names:
        path = destination / name
        if path.is_symlink() or not path.is_file():
            raise PublishError(f"Release asset was not downloaded: {name}")


def upload(tag: str, paths: list[Path], *, clobber: bool = False) -> None:
    if not paths:
        return
    args = ["release", "upload"]
    if clobber:
        args.append("--clobber")
    checked(*args, "--", tag, *(str(path) for path in paths))


def check_hashes(directory: Path, hashes: dict[str, str], server_assets: dict[str, dict]) -> None:
    for name, expected_hash in hashes.items():
        actual = digest(directory / name)
        if actual != expected_hash:
            raise PublishError(f"Release checksum mismatch: {name}")
        server_hash = server_assets.get(name, {}).get("digest")
        if server_hash and server_hash.startswith("sha256:") and server_hash[7:].lower() != actual:
            raise PublishError(f"GitHub asset digest mismatch: {name}")


def verify_complete(tag: str, expected: dict[str, str], destination: Path,
                    server_assets: dict[str, dict] | None = None) -> None:
    download(tag, sorted(expected) + ["SHA256SUMS"], destination)
    manifest = parse_manifest(destination / "SHA256SUMS", set(expected))
    if manifest != expected:
        raise PublishError("Release SHA256SUMS differs from the verified assets")
    check_hashes(destination, expected, server_assets or {})


def publish(assets: Path, tag: str, repo: str) -> None:
    if not tag or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise PublishError("Provide a tag and repository in owner/name form")
    # gh release subcommands use GH_REPO; keep it consistent with the API lookup.
    os.environ["GH_REPO"] = repo
    assets = assets.resolve()
    packaging = packaging_module()
    packaging.checksum_assets(assets)
    version = packaging.artifact_version(tag)
    names = {
        f"netcrow-{version}-{target}{'.zip' if 'windows' in target else '.tar.gz'}"
        for target in packaging.TARGETS
    }
    candidate = parse_manifest(assets / "SHA256SUMS", names)
    release = metadata(repo, tag)
    if release is None:
        checked("release", "create", "--verify-tag", "--draft", "--generate-notes",
                "--title", tag, "--", tag)
        release = metadata(repo, tag)
        if release is None:
            raise PublishError("New release was not found after creation")

    with tempfile.TemporaryDirectory(prefix="netcrow-publish-") as directory:
        temporary = Path(directory)
        existing = assets_by_name(release)
        if release["draft"]:
            if release.get("immutable", False):
                raise PublishError("The release is immutable; its draft assets cannot be changed")
            upload(tag, [assets / name for name in sorted(names)] + [assets / "SHA256SUMS"], clobber=True)
            verify_complete(tag, candidate, temporary / "verify")
            checked("release", "edit", "--verify-tag", "--draft=false", "--", tag)
            print("Published verified release.")
            return

        present = names.intersection(existing)
        missing = names.difference(present)
        has_manifest = "SHA256SUMS" in existing
        # Never alter already-published bytes, including on reruns with a new compiler.
        needed_downloads = sorted(present) + (["SHA256SUMS"] if has_manifest else [])
        previous = temporary / "previous"
        download(tag, needed_downloads, previous)
        if has_manifest:
            final_hashes = parse_manifest(previous / "SHA256SUMS", names)
            check_hashes(previous, {name: final_hashes[name] for name in present}, existing)
            if not missing:
                print("Existing published release is complete and verified.")
                return
        else:
            final_hashes = {name: digest(previous / name) for name in present}
            check_hashes(previous, final_hashes, existing)
            final_hashes.update({name: candidate[name] for name in missing})

        if release.get("immutable", False):
            raise PublishError("Published release is immutable and incomplete; missing assets cannot be uploaded")
        if has_manifest:
            conflicts = [name for name in sorted(missing) if candidate[name] != final_hashes[name]]
            if conflicts:
                raise PublishError("Missing build assets do not match the existing SHA256SUMS: " + ", ".join(conflicts))

        upload(tag, [assets / name for name in sorted(missing)])
        if not has_manifest:
            # Verify all archives before adding their manifest, including older assets.
            assembled = temporary / "assembled"
            download(tag, sorted(names), assembled)
            check_hashes(assembled, final_hashes, existing)
            manifest = temporary / "SHA256SUMS"
            write_manifest(manifest, final_hashes)
            upload(tag, [manifest])
        verify_complete(tag, final_hashes, temporary / "verify", existing)
        print("Completed published release without overwriting existing assets.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", default=os.environ.get("RELEASE_TAG"))
    parser.add_argument("--assets", type=Path, default=Path("dist"))
    parser.add_argument("--repo", default=os.environ.get("GH_REPO"))
    args = parser.parse_args()
    if not args.tag or not args.repo:
        parser.error("--tag and --repo (or RELEASE_TAG and GH_REPO) are required")
    try:
        publish(args.assets, args.tag, args.repo)
    except (PublishError, OSError, ValueError) as error:
        parser.exit(1, f"Release publication failed: {error}\n")


if __name__ == "__main__":
    main()

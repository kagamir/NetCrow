"""Regression coverage for resumable GitHub release publication, without network."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock
from urllib.parse import quote


ROOT = Path(__file__).resolve().parents[1]


def load_script(name):
    spec = importlib.util.spec_from_file_location(
        name.replace("-", "_"), ROOT / "scripts" / f"{name}.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


packaging = load_script("package-release")
publisher = load_script("publish-release")


class FakeGitHub:
    """Model remote release state and assert every command remains an argv list."""

    def __init__(self, tag, *, exists=True, draft=False, assets=None, view_error=None,
                 immutable=False, corrupt_download=None, missing_download=None,
                 fallback_error=None):
        self.tag = tag
        self.exists = exists
        self.draft = draft
        self.assets = dict(assets or {})
        self.view_error = view_error
        self.immutable = immutable
        self.corrupt_download = corrupt_download
        self.missing_download = missing_download
        self.fallback_error = fallback_error
        self.commands = []
        self.mutations = []

    def run(self, command, **kwargs):
        if not isinstance(command, (list, tuple)):
            raise AssertionError("release commands must use argv, never a shell string")
        if kwargs.get("shell"):
            raise AssertionError("release commands must not execute through a shell")
        args = [str(value) for value in command]
        self.commands.append(args)
        if args[:2] == ["gh", "api"]:
            expected = f"repos/kagamir/NetCrow/releases/tags/{quote(self.tag, safe='')}"
            by_id = "repos/kagamir/NetCrow/releases/123"
            if len(args) != 3 or args[2] not in (expected, by_id):
                raise AssertionError(f"tag must be quoted as one API path component: {args!r}")
            if self.view_error:
                return self.result(args, 1, stderr=self.view_error, **kwargs)
            # GitHub's by-tag REST endpoint does not return draft releases.
            if not self.exists or (self.draft and args[2] == expected):
                return self.result(args, 1, stderr="gh: Not Found (HTTP 404)", **kwargs)
            response = {
                "id": 123,
                "draft": self.draft,
                "immutable": self.immutable,
                "assets": [
                    {"name": name, "size": len(content),
                     "digest": f"sha256:{hashlib.sha256(content).hexdigest()}"}
                    for name, content in sorted(self.assets.items())
                ],
            }
            return self.result(args, stdout=json.dumps(response), **kwargs)
        if args[:2] != ["gh", "release"]:
            raise AssertionError(f"unexpected external command: {args!r}")
        operation = args[2]
        before, separator, after = self.split_args(args[3:])
        if not separator or not after or after[0] != self.tag:
            raise AssertionError(f"tag must be preserved as one positional argument after --: {args!r}")
        if operation == "view":
            if self.fallback_error:
                return self.result(args, 1, stderr=self.fallback_error, **kwargs)
            if not self.exists:
                return self.result(args, 1, stderr="release not found", **kwargs)
            if self.option(before, "--json") != "databaseId" or self.option(before, "--jq") != ".databaseId":
                raise AssertionError("draft discovery must request its numeric database ID")
            return self.result(args, stdout="123\n", **kwargs)
        if operation == "create":
            if self.exists:
                raise AssertionError("must not create an existing release")
            if "--draft" not in before:
                raise AssertionError("fresh releases must remain draft until verified")
            self.exists = self.draft = True
            self.mutations.append(("create", self.draft))
            return self.result(args, **kwargs)
        if operation == "upload":
            if not self.exists:
                raise AssertionError("cannot upload without a release")
            if not self.draft and "--clobber" in before:
                raise AssertionError("published release uploads must never request clobber")
            for item in after[1:]:
                path = Path(item)
                name = path.name
                if name in self.assets and "--clobber" not in before:
                    return self.result(args, 1, stderr=f"asset already exists: {name}", **kwargs)
                if name in self.assets and not self.draft:
                    raise AssertionError("published assets must never be overwritten")
                self.assets[name] = path.read_bytes()
                self.mutations.append(("upload", name, self.draft))
            return self.result(args, **kwargs)
        if operation == "download":
            destination = Path(self.option(before, "--dir"))
            destination.mkdir(parents=True, exist_ok=True)
            patterns = self.options(before, "--pattern")
            if not patterns:
                patterns = list(self.assets)
            matched = [name for name in patterns if name in self.assets
                       and name != self.missing_download]
            # gh reports success if any supplied pattern matches; the caller must
            # check that every expected file actually appeared after download.
            if not matched:
                return self.result(args, 1, stderr="no assets match the file pattern", **kwargs)
            for name in matched:
                content = self.assets[name]
                if name == self.corrupt_download:
                    content += b"download corruption"
                (destination / name).write_bytes(content)
            return self.result(args, **kwargs)
        if operation == "edit":
            if "--draft=false" not in before:
                raise AssertionError(f"unexpected release edit: {args!r}")
            self.draft = False
            self.mutations.append(("publish",))
            return self.result(args, **kwargs)
        raise AssertionError(f"unsupported fake gh operation: {operation}")

    @staticmethod
    def split_args(args):
        if "--" not in args:
            return args, False, []
        index = args.index("--")
        return args[:index], True, args[index + 1:]

    @staticmethod
    def options(args, name):
        values = []
        for index, arg in enumerate(args):
            if arg == name:
                values.append(args[index + 1])
            elif arg.startswith(name + "="):
                values.append(arg[len(name) + 1:])
        return values

    @classmethod
    def option(cls, args, name):
        values = cls.options(args, name)
        if len(values) != 1:
            raise AssertionError(f"expected one {name}: {args!r}")
        return values[0]

    @staticmethod
    def result(args, returncode=0, stdout="", stderr="", **kwargs):
        result = subprocess.CompletedProcess(args, returncode, stdout=stdout, stderr=stderr)
        if returncode and kwargs.get("check"):
            raise subprocess.CalledProcessError(returncode, args, output=stdout, stderr=stderr)
        return result


class ReleasePublishingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="netcrow-publish-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.dist = self.directory / "dist"
        self.dist.mkdir()
        self.tag = "v1.2.3"
        self.make_assets(self.tag)

    def make_assets(self, tag):
        for path in self.dist.iterdir():
            path.unlink()
        for target in packaging.TARGETS:
            extension = ".zip" if "windows" in target else ".tar.gz"
            name = f"netcrow-{packaging.artifact_version(tag)}-{target}{extension}"
            (self.dist / name).write_bytes(b"archive fixture\x00" + target.encode())
        packaging.checksum_assets(self.dist)
        self.assets = {path.name: path.read_bytes() for path in self.dist.iterdir()}

    def publish(self, remote, *, tag=None):
        with mock.patch.object(publisher.subprocess, "run", side_effect=remote.run), \
                mock.patch.dict(publisher.os.environ), mock.patch("builtins.print"):
            return publisher.publish(self.dist, self.tag if tag is None else tag, "kagamir/NetCrow")

    def assert_complete(self, remote):
        self.assertFalse(remote.draft)
        self.assertEqual(remote.assets, self.assets)

    def test_fresh_release_is_draft_until_all_assets_are_verified(self):
        remote = FakeGitHub(self.tag, exists=False)
        self.publish(remote)
        self.assert_complete(remote)
        self.assertEqual(remote.mutations[0], ("create", True))
        self.assertEqual(remote.mutations[-1], ("publish",))
        uploaded = [mutation for mutation in remote.mutations if mutation[0] == "upload"]
        self.assertEqual({item[1] for item in uploaded}, set(self.assets))
        self.assertTrue(all(item[2] for item in uploaded), "uploads must precede publication")
        operations = [command[2] for command in remote.commands]
        self.assertLess(operations.index("download"), operations.index("edit"))
        self.assertGreaterEqual(operations.count("view"), 2,
                                "fresh draft lookup must survive REST by-tag 404")

    def test_failed_fresh_download_verification_leaves_release_draft(self):
        name = next(name for name in self.assets if name != "SHA256SUMS")
        remote = FakeGitHub(self.tag, exists=False, corrupt_download=name)
        with self.assertRaisesRegex((ValueError, RuntimeError), "(?i)(checksum|sha256|digest|match)"):
            self.publish(remote)
        self.assertTrue(remote.draft)
        self.assertNotIn(("publish",), remote.mutations)

    def test_gh_partial_download_success_does_not_publish_an_incomplete_draft(self):
        name = next(name for name in self.assets if name != "SHA256SUMS")
        remote = FakeGitHub(self.tag, exists=False, missing_download=name)
        with self.assertRaisesRegex((ValueError, RuntimeError), "(?i)(not downloaded|missing)"):
            self.publish(remote)
        self.assertTrue(remote.draft)
        self.assertNotIn(("publish",), remote.mutations)

    def test_existing_published_empty_release_uploads_complete_asset_set(self):
        # The production regression: isDraft=false did not imply assets existed.
        remote = FakeGitHub(self.tag, draft=False, assets={})
        self.publish(remote)
        self.assert_complete(remote)
        self.assertEqual({item[1] for item in remote.mutations}, set(self.assets))
        self.assertTrue(all(item[0] == "upload" for item in remote.mutations))

    def test_existing_published_partial_release_only_fills_missing_assets(self):
        present = sorted(self.assets)[:3]
        before = {name: self.assets[name] for name in present}
        remote = FakeGitHub(self.tag, assets=before)
        self.publish(remote)
        self.assert_complete(remote)
        uploaded = {item[1] for item in remote.mutations if item[0] == "upload"}
        self.assertEqual(uploaded, set(self.assets) - set(present))
        self.assertEqual({name: remote.assets[name] for name in present}, before)
        self.assertTrue(all(item[0] == "upload" for item in remote.mutations))

    def test_existing_draft_can_be_repaired_before_publication(self):
        name = next(name for name in self.assets if name != "SHA256SUMS")
        remote = FakeGitHub(self.tag, draft=True, assets={name: b"interrupted draft build"})
        self.publish(remote)
        self.assert_complete(remote)
        self.assertNotIn(("create", True), remote.mutations)
        self.assertEqual(remote.mutations[-1], ("publish",))
        self.assertTrue(all(item[2] for item in remote.mutations if item[0] == "upload"))
        self.assertIn("view", [command[2] for command in remote.commands])

    def test_complete_published_rerun_only_verifies_downloaded_assets(self):
        remote = FakeGitHub(self.tag, assets=self.assets)
        self.publish(remote)
        self.assert_complete(remote)
        self.assertEqual(remote.mutations, [])
        self.assertIn("download", [command[2] for command in remote.commands])

    def test_complete_published_assets_need_not_match_rebuilt_local_bytes(self):
        remote = FakeGitHub(self.tag, assets=self.assets)
        rebuilt = next(path for path in self.dist.iterdir() if path.name != "SHA256SUMS")
        rebuilt.write_bytes(b"a valid later rebuild can differ from the original")
        packaging.checksum_assets(self.dist)
        self.publish(remote)
        self.assert_complete(remote)
        self.assertEqual(remote.mutations, [])

    def test_partial_published_without_manifest_preserves_original_bytes(self):
        present = sorted(name for name in self.assets if name != "SHA256SUMS")[:2]
        originals = {name: b"originally published build\x00" + self.assets[name] for name in present}
        remote = FakeGitHub(self.tag, assets=originals)
        self.publish(remote)
        self.assertFalse(remote.draft)
        expected = {**self.assets, **originals}
        manifest = "".join(
            f"{hashlib.sha256(expected[name]).hexdigest()}  {name}\n"
            for name in sorted(expected) if name != "SHA256SUMS"
        ).encode()
        expected["SHA256SUMS"] = manifest
        self.assertEqual(remote.assets, expected)
        self.assertEqual(remote.mutations[-1][1], "SHA256SUMS")
        self.assertEqual({item[1] for item in remote.mutations}, set(self.assets) - set(present))
        self.assertTrue(all(item[0] == "upload" for item in remote.mutations))

    def test_corrupt_published_checksum_fails_without_overwrite_or_republication(self):
        corrupted = dict(self.assets)
        name = next(name for name in corrupted if name != "SHA256SUMS")
        corrupted[name] += b"corrupted after publication"
        remote = FakeGitHub(self.tag, assets=corrupted)
        with self.assertRaisesRegex((ValueError, RuntimeError), "(?i)(checksum|sha256|digest|match)"):
            self.publish(remote)
        self.assertEqual(remote.mutations, [])
        self.assertEqual(remote.assets, corrupted)
        self.assertFalse(remote.draft)

    def test_partial_manifest_rejects_incompatible_missing_rebuild_before_upload(self):
        missing = next(name for name in self.assets if name != "SHA256SUMS")
        published = {name: content for name, content in self.assets.items() if name != missing}
        remote = FakeGitHub(self.tag, assets=published)
        (self.dist / missing).write_bytes(b"this rebuild differs from the published SHA256SUMS")
        packaging.checksum_assets(self.dist)
        with self.assertRaisesRegex((ValueError, RuntimeError), "(?i)(checksum|sha256|digest|match)"):
            self.publish(remote)
        self.assertEqual(remote.mutations, [])
        self.assertEqual(remote.assets, published)

    def test_lookup_failure_other_than_404_does_not_create_release(self):
        for error in ("HTTP 403: Resource not accessible by integration", "HTTP 500: Internal Server Error", "network timeout"):
            with self.subTest(error=error):
                remote = FakeGitHub(self.tag, exists=False, view_error=error)
                with self.assertRaises((ValueError, RuntimeError, subprocess.CalledProcessError)):
                    self.publish(remote)
                self.assertFalse(remote.exists)
                self.assertEqual(remote.mutations, [])

    def test_incomplete_immutable_release_fails_without_attempted_mutation(self):
        remote = FakeGitHub(self.tag, assets={}, immutable=True)
        with self.assertRaisesRegex((ValueError, RuntimeError), "(?i)immutable"):
            self.publish(remote)
        self.assertEqual(remote.mutations, [])

    def test_draft_lookup_permission_failure_is_not_mistaken_for_absence(self):
        remote = FakeGitHub(self.tag, exists=False,
                            fallback_error="GraphQL: Resource not accessible by integration")
        with self.assertRaises((ValueError, RuntimeError, subprocess.CalledProcessError)):
            self.publish(remote)
        self.assertFalse(remote.exists)
        self.assertEqual(remote.mutations, [])

    def test_tag_is_one_literal_argument_after_option_separator(self):
        for tag in ("-version", "release/v1", "$(touch should-not-exist)"):
            with self.subTest(tag=tag):
                self.make_assets(tag)
                remote = FakeGitHub(tag, exists=False)
                self.publish(remote, tag=tag)
                self.assert_complete(remote)
                self.assertEqual(remote.tag, tag)
                self.assertFalse((self.directory / "should-not-exist").exists())


if __name__ == "__main__":
    unittest.main()

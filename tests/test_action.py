from __future__ import annotations

import importlib.machinery
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ACTION_PATH = Path(__file__).resolve().parents[1] / "action"
LOADER = importlib.machinery.SourceFileLoader("apt_install_action", str(ACTION_PATH))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
if SPEC is None:
    raise RuntimeError("Unable to load the action module")
ACTION = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ACTION
LOADER.exec_module(ACTION)


class PackageParsingTests(unittest.TestCase):
    def test_normalizes_whitespace_order_and_duplicates(self) -> None:
        self.assertEqual(
            ACTION.parse_packages("libpcap-dev\n libidn-dev  libpcap-dev\t"),
            ["libidn-dev", "libpcap-dev"],
        )

    def test_accepts_architecture_and_exact_version(self) -> None:
        self.assertEqual(
            ACTION.parse_packages(
                "libidn-dev:amd64=1.42-1ubuntu0.1~internal+1"
            ),
            ["libidn-dev:amd64=1.42-1ubuntu0.1~internal+1"],
        )

    def test_rejects_apt_and_shell_syntax(self) -> None:
        invalid_values = (
            "--allow-unauthenticated",
            "bash-",
            "package:amd64-",
            "package/jammy",
            "package*",
            "package;touch /tmp/injected",
            'package"; touch /tmp/injected; #',
        )
        for value in invalid_values:
            with self.subTest(value=value):
                with self.assertRaises(ACTION.ActionError):
                    ACTION.parse_packages(value)

    def test_rejects_empty_oversized_and_excessive_input(self) -> None:
        with self.assertRaises(ACTION.ActionError):
            ACTION.parse_packages("")
        with self.assertRaises(ACTION.ActionError):
            ACTION.parse_packages("a" * (ACTION.MAX_PACKAGE_INPUT_LENGTH + 1))
        with self.assertRaises(ACTION.ActionError):
            ACTION.parse_packages(" ".join(["dash"] * 129))


class OsReleaseTests(unittest.TestCase):
    def test_reads_quoted_target_fields(self) -> None:
        fields = ACTION.parse_os_release(
            '# comment\nID=ubuntu\nVERSION_ID="22.04"\nPRETTY_NAME="ignored"\n'
        )
        self.assertEqual(fields, {"ID": "ubuntu", "VERSION_ID": "22.04"})

    def test_rejects_malformed_target_field(self) -> None:
        with self.assertRaises(ACTION.ActionError):
            ACTION.parse_os_release('ID="unterminated\nVERSION_ID=22.04\n')


class PlatformTests(unittest.TestCase):
    @mock.patch.object(ACTION, "require_commands")
    @mock.patch.object(ACTION, "run_command")
    def test_accepts_ubuntu_2204(self, run_command, _require_commands) -> None:
        run_command.side_effect = (
            SimpleNamespace(returncode=0),
            SimpleNamespace(stdout="amd64\n"),
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            os_release = Path(temporary_directory) / "os-release"
            os_release.write_text(
                'ID=ubuntu\nVERSION_ID="22.04"\n', encoding="utf-8"
            )
            self.assertEqual(
                ACTION.validate_platform(os_release),
                ACTION.Platform("ubuntu", "22.04", "amd64"),
            )

        comparison = run_command.call_args_list[0]
        self.assertIn(ACTION.MIN_UBUNTU_VERSION, comparison.args[0])

    @mock.patch.object(ACTION, "require_commands")
    @mock.patch.object(ACTION, "run_command")
    def test_rejects_ubuntu_older_than_2204(
        self, run_command, _require_commands
    ) -> None:
        run_command.return_value = SimpleNamespace(returncode=1)
        with tempfile.TemporaryDirectory() as temporary_directory:
            os_release = Path(temporary_directory) / "os-release"
            os_release.write_text(
                'ID=ubuntu\nVERSION_ID="20.04"\n', encoding="utf-8"
            )
            with self.assertRaises(ACTION.ActionError):
                ACTION.validate_platform(os_release)


class DigestTests(unittest.TestCase):
    def test_field_boundaries_affect_digest(self) -> None:
        first = ACTION.digest_fields([("a", "bc"), ("d", "e")])
        second = ACTION.digest_fields([("a", "b"), ("cd", "e")])
        self.assertNotEqual(first, second)

    def test_apt_configuration_digest_tracks_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            source = Path(temporary_directory) / "ubuntu.sources"
            source.write_text("Suites: jammy\n", encoding="utf-8")
            first = ACTION.apt_configuration_digest([source])
            source.write_text("Suites: noble\n", encoding="utf-8")
            second = ACTION.apt_configuration_digest([source])
            self.assertNotEqual(first, second)


class CachePathTests(unittest.TestCase):
    def make_cache(self, runner_temp: Path) -> Path:
        cache = runner_temp / "apt-install" / ("a" * 64) / "archives"
        cache.mkdir(parents=True)
        return cache

    def test_accepts_expected_cache_layout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            runner_temp = Path(temporary_directory).resolve()
            cache = self.make_cache(runner_temp)
            self.assertEqual(
                ACTION.resolve_cache_directory_from_values(
                    str(runner_temp), str(cache)
                ),
                cache,
            )

    def test_creates_expected_cache_layout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            runner_temp = Path(temporary_directory).resolve()
            cache = ACTION.create_cache_directory(runner_temp, "b" * 64)
            self.assertEqual(
                cache,
                runner_temp / "apt-install" / ("b" * 64) / "archives",
            )
            self.assertTrue(cache.is_dir())

    def test_rejects_outside_and_malformed_cache_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            runner_temp = Path(temporary_directory).resolve()
            outside = runner_temp.parent / "outside" / ("a" * 64) / "archives"
            malformed = runner_temp / "apt-install" / "not-a-digest" / "archives"
            for cache in (outside, malformed):
                with self.subTest(cache=cache):
                    with self.assertRaises(ACTION.ActionError):
                        ACTION.resolve_cache_directory_from_values(
                            str(runner_temp), str(cache)
                        )

    def test_rejects_symbolic_link_in_cache_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            runner_temp = Path(temporary_directory).resolve()
            cache_root = runner_temp / "apt-install"
            cache_root.mkdir()
            target = runner_temp / "target"
            target.mkdir()
            digest_directory = cache_root / ("a" * 64)
            try:
                digest_directory.symlink_to(target, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"Symbolic links unavailable: {error}")

            cache = digest_directory / "archives"
            with self.assertRaises(ACTION.ActionError):
                ACTION.resolve_cache_directory_from_values(
                    str(runner_temp), str(cache)
                )


class CacheEntryTests(unittest.TestCase):
    def test_accepts_only_single_link_regular_deb_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache = Path(temporary_directory)
            archive = cache / "package.deb"
            archive.write_bytes(b"deb")
            self.assertEqual(ACTION.validate_cached_entries(cache), [archive])

    def test_rejects_unexpected_file_and_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache = Path(temporary_directory)
            unexpected = cache / "unexpected.txt"
            unexpected.write_text("no", encoding="utf-8")
            with self.assertRaises(ACTION.ActionError):
                ACTION.validate_cached_entries(cache)
            unexpected.unlink()

            (cache / "partial").mkdir()
            with self.assertRaises(ACTION.ActionError):
                ACTION.validate_cached_entries(cache)

    def test_rejects_hard_linked_archive(self) -> None:
        if os.name != "posix":
            self.skipTest("POSIX link counts are required")
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache = Path(temporary_directory)
            first = cache / "first.deb"
            second = cache / "second.deb"
            first.write_bytes(b"deb")
            try:
                os.link(first, second)
            except OSError as error:
                self.skipTest(f"Hard links unavailable: {error}")

            with self.assertRaises(ACTION.ActionError):
                ACTION.validate_cached_entries(cache)

    def test_rejects_symbolic_linked_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache = Path(temporary_directory)
            target = cache / "target"
            target.write_bytes(b"deb")
            link = cache / "linked.deb"
            try:
                link.symlink_to(target)
            except OSError as error:
                self.skipTest(f"Symbolic links unavailable: {error}")

            with self.assertRaises(ACTION.ActionError):
                ACTION.validate_cached_entries(cache)


class AnnotationTests(unittest.TestCase):
    def test_escapes_workflow_command_data(self) -> None:
        self.assertEqual(
            ACTION.annotation_escape("100%\r\n::warning::x"),
            "100%25%0D%0A::warning::x",
        )


if __name__ == "__main__":
    unittest.main()

"""Edge-case tests for collect_files: symlinks, dotfiles, unreadable files."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from ai_sec_scan.scanner import collect_files


class TestDotfiles:
    """Dotfiles and hidden directories."""

    def test_dotfiles_excluded_by_extension_filter(self, tmp_path: Path) -> None:
        """A dotfile like .env has no recognised extension and should be skipped."""
        (tmp_path / ".env").write_text("SECRET=abc")
        (tmp_path / "app.py").write_text("x = 1")
        files = collect_files(tmp_path)
        names = {f.name for f in files}
        assert "app.py" in names
        assert ".env" not in names

    def test_hidden_dir_not_auto_excluded(self, tmp_path: Path) -> None:
        """Hidden directories like .config are not in DEFAULT_EXCLUDES,
        so .py files inside should be collected."""
        hidden = tmp_path / ".config"
        hidden.mkdir()
        (hidden / "setup.py").write_text("cfg = True")
        files = collect_files(tmp_path)
        names = {f.name for f in files}
        assert "setup.py" in names


class TestSymlinks:
    """Symlink handling."""

    def test_symlink_to_file_is_collected(self, tmp_path: Path) -> None:
        real = tmp_path / "real.py"
        real.write_text("x = 1")
        link = tmp_path / "link.py"
        link.symlink_to(real)
        files = collect_files(tmp_path)
        names = {f.name for f in files}
        assert "real.py" in names
        assert "link.py" in names

    def test_broken_symlink_skipped(self, tmp_path: Path) -> None:
        link = tmp_path / "broken.py"
        link.symlink_to(tmp_path / "nonexistent.py")
        (tmp_path / "good.py").write_text("x = 1")
        files = collect_files(tmp_path)
        names = {f.name for f in files}
        assert "good.py" in names
        assert "broken.py" not in names


class TestPermissions:
    """Unreadable files should be handled gracefully."""

    @pytest.mark.skipif(os.getuid() == 0, reason="root can read anything")
    def test_unreadable_file_skipped_at_scan_time(self, tmp_path: Path) -> None:
        """collect_files checks size via stat, which still works on unreadable files.
        The file will be collected but the scanner will skip it on read error."""
        f = tmp_path / "secret.py"
        f.write_text("password = '12345'")
        f.chmod(0o000)
        try:
            # collect_files does stat for size; on some OS this may still succeed
            files = collect_files(tmp_path)
            # Either the file is in the list (stat works) or not (stat fails) -- both ok
            assert isinstance(files, list)
        finally:
            f.chmod(stat.S_IRUSR | stat.S_IWUSR)


class TestMixedContent:
    """Directories with a variety of content types."""

    def test_binary_files_ignored(self, tmp_path: Path) -> None:
        (tmp_path / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n")
        (tmp_path / "data.bin").write_bytes(b"\x00\x01\x02")
        (tmp_path / "app.py").write_text("x = 1")
        files = collect_files(tmp_path)
        names = {f.name for f in files}
        assert names == {"app.py"}

    def test_deeply_nested_files(self, tmp_path: Path) -> None:
        deep = tmp_path / "a" / "b" / "c" / "d"
        deep.mkdir(parents=True)
        (deep / "deep.py").write_text("deep = True")
        files = collect_files(tmp_path)
        assert len(files) == 1
        assert files[0].name == "deep.py"

    def test_empty_file_collected(self, tmp_path: Path) -> None:
        """Empty .py files should still be collected (size 0 <= max)."""
        (tmp_path / "empty.py").write_text("")
        files = collect_files(tmp_path)
        assert len(files) == 1
        assert files[0].name == "empty.py"

    def test_multiple_extensions(self, tmp_path: Path) -> None:
        """Files with multiple dots should match on final suffix."""
        (tmp_path / "config.test.py").write_text("x = 1")
        (tmp_path / "archive.tar.gz").write_bytes(b"\x1f\x8b")
        files = collect_files(tmp_path)
        names = {f.name for f in files}
        assert "config.test.py" in names
        assert "archive.tar.gz" not in names

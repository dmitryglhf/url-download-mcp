"""Tests for utility functions in the MCP URL Downloader."""

from mcp_url_downloader.server import (
    _extract_filename_from_url,
    _get_unique_filepath,
    _sanitize_filename,
)


class TestSanitizeFilename:
    """Tests for _sanitize_filename function."""

    def test_sanitize_normal_filename(self):
        """Test sanitization of a normal filename."""
        result = _sanitize_filename("document.pdf")
        assert result == "document.pdf"

    def test_sanitize_filename_with_spaces(self):
        """Test sanitization of filename with spaces."""
        result = _sanitize_filename("my document.pdf")
        assert result == "my document.pdf"

    def test_sanitize_filename_with_special_chars(self):
        """Test sanitization of filename with special characters."""
        result = _sanitize_filename('file<>:"|?*.txt')
        assert result == "file_______.txt"  # 7 underscores for 7 special chars

    def test_sanitize_filename_with_path_separators(self):
        """Test sanitization removes path separators."""
        result = _sanitize_filename("../../../etc/passwd")
        # Leading dots are stripped, slashes become underscores
        assert result == "_.._.._etc_passwd"

    def test_sanitize_filename_with_leading_dots(self):
        """Test sanitization removes leading dots."""
        result = _sanitize_filename("...file.txt")
        assert result == "file.txt"

    def test_sanitize_filename_with_trailing_spaces(self):
        """Test sanitization removes trailing spaces."""
        result = _sanitize_filename("file.txt   ")
        assert result == "file.txt"

    def test_sanitize_empty_filename(self):
        """Test sanitization of empty filename."""
        result = _sanitize_filename("")
        assert result == "downloaded_file"

    def test_sanitize_only_special_chars(self):
        """Test sanitization of filename with only special characters."""
        result = _sanitize_filename("<<<>>>")
        # Special chars become underscores, not empty after strip
        assert result == "______"

    def test_sanitize_very_long_filename(self):
        """Test sanitization of very long filename."""
        long_name = "a" * 300 + ".txt"
        result = _sanitize_filename(long_name)
        assert len(result) <= 255
        assert result.endswith(".txt")

    def test_sanitize_unicode_filename(self):
        """Test sanitization preserves unicode characters."""
        result = _sanitize_filename("файл.pdf")
        assert result == "файл.pdf"


class TestExtractFilenameFromUrl:
    """Tests for _extract_filename_from_url function."""

    def test_extract_simple_filename(self):
        """Test extraction of simple filename from URL."""
        url = "https://example.com/document.pdf"
        result = _extract_filename_from_url(url)
        assert result == "document.pdf"

    def test_extract_filename_with_path(self):
        """Test extraction of filename from URL with path."""
        url = "https://example.com/files/reports/document.pdf"
        result = _extract_filename_from_url(url)
        assert result == "document.pdf"

    def test_extract_filename_with_query_params(self):
        """Test extraction of filename from URL with query parameters."""
        url = "https://example.com/document.pdf?version=1&download=true"
        result = _extract_filename_from_url(url)
        assert result == "document.pdf"

    def test_extract_filename_from_query_param(self):
        """Test extraction of filename from query parameter when path is empty."""
        url = "https://example.com/?filename=report.pdf"
        result = _extract_filename_from_url(url)
        assert result == "report.pdf"

    def test_extract_filename_url_encoded(self):
        """Test extraction of URL-encoded filename."""
        url = "https://example.com/my%20document.pdf"
        result = _extract_filename_from_url(url)
        assert result == "my document.pdf"

    def test_extract_filename_no_extension(self):
        """Test extraction when filename has no extension."""
        url = "https://example.com/download"
        result = _extract_filename_from_url(url)
        assert result == "download.bin"

    def test_extract_filename_empty_path(self):
        """Test extraction when URL has no path."""
        url = "https://example.com/"
        result = _extract_filename_from_url(url)
        assert result == "downloaded_file.bin"

    def test_extract_filename_with_fragment(self):
        """Test extraction of filename from URL with fragment."""
        url = "https://example.com/document.pdf#page=1"
        result = _extract_filename_from_url(url)
        assert result == "document.pdf"

    def test_extract_filename_special_chars(self):
        """Test extraction of filename with special characters."""
        url = "https://example.com/file%3Aname.pdf"
        result = _extract_filename_from_url(url)
        # Should be sanitized
        assert ":" not in result or "_" in result


class TestGetUniqueFilepath:
    """Tests for _get_unique_filepath function."""

    def test_unique_filepath_no_collision(self, temp_dir):
        """Test unique filepath when no collision exists."""
        file_path = temp_dir / "test.txt"
        result = _get_unique_filepath(file_path)
        assert result == file_path

    def test_unique_filepath_with_collision(self, temp_dir):
        """Test unique filepath when collision exists."""
        file_path = temp_dir / "test.txt"
        file_path.touch()  # Create the file

        result = _get_unique_filepath(file_path)
        # Should create unique name with UUID, not test.txt
        assert result != file_path
        assert result.suffix == ".txt"
        assert result.parent == temp_dir
        assert result.stem.startswith("test_")

    def test_unique_filepath_multiple_collisions(self, temp_dir):
        """Test unique filepath with multiple collisions."""
        file_path = temp_dir / "test.txt"
        file_path.touch()
        (temp_dir / "test_1.txt").touch()
        (temp_dir / "test_2.txt").touch()

        result = _get_unique_filepath(file_path)
        # Should always create unique name with UUID
        assert result != file_path
        assert result.suffix == ".txt"
        assert not result.exists()

    def test_unique_filepath_preserves_extension(self, temp_dir):
        """Test unique filepath preserves file extension."""
        file_path = temp_dir / "document.pdf"
        file_path.touch()

        result = _get_unique_filepath(file_path)
        assert result.suffix == ".pdf"
        assert result.stem.startswith("document_")
        assert result.parent == temp_dir

    def test_unique_filepath_no_extension(self, temp_dir):
        """Test unique filepath for file without extension."""
        file_path = temp_dir / "file"
        file_path.touch()

        result = _get_unique_filepath(file_path)
        assert result != file_path
        assert result.stem.startswith("file_")
        assert result.suffix == ""

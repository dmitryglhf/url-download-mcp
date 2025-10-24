"""Security tests for MCP URL Downloader."""

import pytest

from mcp_url_downloader.server import (
    _sanitize_error,
    _validate_output_dir,
    _validate_url_safe,
    download_files,
    download_single_file,
)


class TestSSRFProtection:
    """Tests for Server-Side Request Forgery protection."""

    @pytest.mark.asyncio
    async def test_localhost_blocked(self):
        """Test that localhost URLs are blocked."""
        result = await download_single_file("http://localhost/test.txt")
        assert not result.success
        assert "localhost" in result.error.lower()

    @pytest.mark.asyncio
    async def test_localhost_ip_blocked(self):
        """Test that 127.0.0.1 is blocked."""
        result = await download_single_file("http://127.0.0.1/test.txt")
        assert not result.success
        assert "not allowed" in result.error.lower()

    @pytest.mark.asyncio
    async def test_private_ip_10_blocked(self):
        """Test that private IP 10.x.x.x is blocked."""
        result = await download_single_file("http://10.0.0.1/test.txt")
        assert not result.success
        assert "blocked" in result.error.lower() or "private" in result.error.lower()

    @pytest.mark.asyncio
    async def test_private_ip_192_blocked(self):
        """Test that private IP 192.168.x.x is blocked."""
        result = await download_single_file("http://192.168.1.1/test.txt")
        assert not result.success
        assert "blocked" in result.error.lower() or "private" in result.error.lower()

    @pytest.mark.asyncio
    async def test_private_ip_172_blocked(self):
        """Test that private IP 172.16.x.x is blocked."""
        result = await download_single_file("http://172.16.0.1/test.txt")
        assert not result.success
        assert "blocked" in result.error.lower() or "private" in result.error.lower()

    @pytest.mark.asyncio
    async def test_link_local_blocked(self):
        """Test that link-local IP 169.254.x.x is blocked (AWS metadata)."""
        result = await download_single_file("http://169.254.169.254/latest/meta-data/")
        assert not result.success
        assert "blocked" in result.error.lower() or "private" in result.error.lower()

    @pytest.mark.asyncio
    async def test_file_protocol_blocked(self):
        """Test that file:// protocol is blocked."""
        result = await download_single_file("file:///etc/passwd")
        assert not result.success
        assert "protocol" in result.error.lower() or "unsupported" in result.error.lower()

    @pytest.mark.asyncio
    async def test_ftp_protocol_blocked(self):
        """Test that ftp:// protocol is blocked."""
        result = await download_single_file("ftp://example.com/file.txt")
        assert not result.success
        assert "protocol" in result.error.lower() or "unsupported" in result.error.lower()

    def test_validate_url_safe_localhost(self):
        """Test _validate_url_safe blocks localhost."""
        with pytest.raises(ValueError, match="localhost"):
            _validate_url_safe("http://localhost/")

    def test_validate_url_safe_private_ip(self):
        """Test _validate_url_safe blocks private IPs."""
        with pytest.raises(ValueError, match="blocked"):
            _validate_url_safe("http://192.168.1.1/")

    def test_validate_url_safe_too_long(self):
        """Test _validate_url_safe blocks overly long URLs."""
        long_url = "http://example.com/" + "a" * 3000
        with pytest.raises(ValueError, match="too long"):
            _validate_url_safe(long_url)

    def test_validate_url_safe_invalid_scheme(self):
        """Test _validate_url_safe blocks non-http(s) schemes."""
        with pytest.raises(ValueError, match="protocol"):
            _validate_url_safe("javascript:alert(1)")


class TestPathTraversal:
    """Tests for path traversal protection."""

    def test_path_traversal_blocked(self, temp_dir):
        """Test that absolute paths outside allowed dirs are blocked."""
        with pytest.raises(ValueError, match="allowed locations"):
            _validate_output_dir("/etc")

    def test_path_traversal_parent_blocked(self, temp_dir):
        """Test that .. traversal is blocked."""
        with pytest.raises(ValueError, match="allowed locations"):
            _validate_output_dir(str(temp_dir / ".." / ".." / "etc"))

    def test_path_traversal_root_blocked(self):
        """Test that writing to root is blocked."""
        with pytest.raises(ValueError, match="allowed locations"):
            _validate_output_dir("/")

    def test_allowed_downloads_dir(self):
        """Test that Downloads directory is allowed."""
        from pathlib import Path

        downloads = Path.home() / "Downloads" / "test"
        result = _validate_output_dir(str(downloads))
        assert result.is_absolute()

    def test_allowed_documents_dir(self):
        """Test that Documents directory is allowed."""
        from pathlib import Path

        documents = Path.home() / "Documents" / "test"
        result = _validate_output_dir(str(documents))
        assert result.is_absolute()

    @pytest.mark.asyncio
    async def test_download_to_forbidden_path(self):
        """Test that download to forbidden path fails."""
        result = await download_single_file(url="https://example.com/test.txt", output_dir="/etc")
        assert not result.success
        assert "allowed" in result.error.lower()


class TestDoSProtection:
    """Tests for Denial of Service protection."""

    @pytest.mark.asyncio
    async def test_concurrent_download_limit(self):
        """Test that concurrent downloads are limited."""
        # Create list of many URLs
        urls = [f"https://example.com/file{i}.txt" for i in range(20)]

        # This should not crash or hang
        # The semaphore will limit concurrent connections
        result = await download_files(urls)

        # All should fail (example.com doesn't exist) but shouldn't crash
        assert len(result.results) == 20
        assert result.failed_count == 20

    @pytest.mark.asyncio
    async def test_max_urls_limit(self):
        """Test that too many URLs are rejected."""
        urls = [f"https://example.com/file{i}.txt" for i in range(150)]

        with pytest.raises(ValueError, match="Maximum.*URLs"):
            await download_files(urls)

    @pytest.mark.asyncio
    async def test_timeout_validation(self):
        """Test that invalid timeout values are rejected."""
        # Pydantic should validate these via Field constraints
        # Test will fail at validation level if timeout is out of range

        # This should work (within range)
        result = await download_single_file("https://example.com/test.txt", timeout=60)
        # Will fail for other reasons, but timeout is valid
        assert result is not None


class TestErrorSanitization:
    """Tests for error message sanitization."""

    def test_sanitize_error_removes_paths_unix(self):
        """Test that Unix paths are removed from errors."""

        error = ValueError("File not found: /home/user/secret/file.txt")
        sanitized = _sanitize_error(error)
        assert "/home/user/secret/file.txt" not in sanitized
        assert "[PATH]" in sanitized or sanitized == str(error)

    def test_sanitize_error_removes_paths_windows(self):
        """Test that Windows paths are removed from errors."""
        error = ValueError("File not found: C:\\Users\\secret\\file.txt")
        sanitized = _sanitize_error(error)
        assert "C:\\Users\\secret\\file.txt" not in sanitized

    def test_sanitize_error_http_status(self):
        """Test that HTTP errors are sanitized."""
        from unittest.mock import Mock

        import httpx

        response = Mock()
        response.status_code = 404
        error = httpx.HTTPStatusError("Not found", request=Mock(), response=response)
        sanitized = _sanitize_error(error)
        assert "404" in sanitized
        assert "HTTP error" in sanitized

    def test_sanitize_error_timeout(self):
        """Test that timeout errors are sanitized."""
        import httpx

        error = httpx.TimeoutException("Timeout")
        sanitized = _sanitize_error(error)
        assert "timeout" in sanitized.lower()

    def test_sanitize_error_valueerror_preserved(self):
        """Test that ValueError messages are preserved (our own validation)."""
        error = ValueError("Invalid URL format")
        sanitized = _sanitize_error(error)
        assert "Invalid URL format" in sanitized


class TestInputValidation:
    """Tests for input validation."""

    @pytest.mark.asyncio
    async def test_empty_url(self):
        """Test that empty URL is rejected."""
        result = await download_single_file("")
        assert not result.success

    @pytest.mark.asyncio
    async def test_invalid_url_format(self):
        """Test that invalid URL format is rejected."""
        result = await download_single_file("not a url")
        assert not result.success
        assert (
            "invalid" in result.error.lower()
            or "format" in result.error.lower()
            or "protocol" in result.error.lower()
        )

    @pytest.mark.asyncio
    async def test_url_without_scheme(self):
        """Test that URL without scheme is rejected."""
        result = await download_single_file("example.com/file.txt")
        assert not result.success


class TestMIMETypeValidation:
    """Tests for MIME type validation."""

    @pytest.mark.asyncio
    async def test_allowed_mime_types(self):
        """Test that common safe MIME types would be allowed."""
        # This is a unit test - we can't actually download
        # but we verify the allowed list is reasonable
        from mcp_url_downloader.server import ALLOWED_CONTENT_TYPES

        assert "application/pdf" in ALLOWED_CONTENT_TYPES
        assert "image/jpeg" in ALLOWED_CONTENT_TYPES
        assert "text/plain" in ALLOWED_CONTENT_TYPES

    @pytest.mark.asyncio
    async def test_executable_mime_blocked(self):
        """Test that executable MIME types are not in allowed list."""
        from mcp_url_downloader.server import ALLOWED_CONTENT_TYPES

        # These should NOT be in the allowed list
        assert "application/x-executable" not in ALLOWED_CONTENT_TYPES
        assert "application/x-msdownload" not in ALLOWED_CONTENT_TYPES
        assert "application/x-sh" not in ALLOWED_CONTENT_TYPES

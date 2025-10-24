"""Tests for download functionality in the MCP URL Downloader."""

from unittest.mock import AsyncMock, Mock, patch

import pytest

from mcp_url_downloader.server import (
    _download_single_file_internal,
    download_files,
    download_single_file,
)


class TestDownloadSingleFileInternal:
    """Tests for _download_single_file_internal function."""

    @pytest.mark.asyncio
    async def test_download_invalid_url(self, temp_dir):
        """Test download with invalid URL."""
        result = await _download_single_file_internal(
            url="not-a-valid-url",
            output_dir=str(temp_dir),
            filename=None,
            timeout=60,
            max_size_mb=500,
        )

        assert result.success is False
        assert result.error is not None
        assert "Invalid URL format" in result.error

    @pytest.mark.asyncio
    async def test_download_file_too_large_from_header(self, temp_dir):
        """Test download fails when file exceeds size limit based on Content-Length header."""
        url = "https://example.com/large.pdf"

        mock_head_response = Mock()
        # 600MB file, but limit is 500MB
        mock_head_response.headers = {"Content-Length": str(600 * 1024 * 1024)}

        with patch("mcp_url_downloader.server.httpx.AsyncClient") as mock_client:
            mock_client_instance = AsyncMock()
            mock_client_instance.head = AsyncMock(return_value=mock_head_response)

            mock_client.return_value.__aenter__.return_value = mock_client_instance
            mock_client.return_value.__aexit__.return_value = None

            result = await _download_single_file_internal(
                url=url,
                output_dir=str(temp_dir),
                filename=None,
                timeout=60,
                max_size_mb=500,
            )

            assert result.success is False
            assert result.error is not None
            assert "exceeds maximum allowed size" in result.error

    @pytest.mark.asyncio
    async def test_download_custom_filename(self, temp_dir):
        """Test that custom filename is used when provided."""
        url = "https://example.com/file.pdf"
        custom_filename = "my_custom_name.pdf"

        # Simulate file too large to avoid actual download
        mock_head_response = Mock()
        mock_head_response.headers = {"Content-Length": str(600 * 1024 * 1024)}

        with patch("mcp_url_downloader.server.httpx.AsyncClient") as mock_client:
            mock_client_instance = AsyncMock()
            mock_client_instance.head = AsyncMock(return_value=mock_head_response)

            mock_client.return_value.__aenter__.return_value = mock_client_instance
            mock_client.return_value.__aexit__.return_value = None

            result = await _download_single_file_internal(
                url=url,
                output_dir=str(temp_dir),
                filename=custom_filename,
                timeout=60,
                max_size_mb=500,
            )

            # Even though download failed, the filename should be set correctly
            assert result.file_name == custom_filename


class TestDownloadFiles:
    """Tests for download_files function."""

    @pytest.mark.asyncio
    async def test_download_files_empty_list(self, temp_dir):
        """Test downloading with empty URL list."""
        result = await download_files(urls=[], output_dir=str(temp_dir))

        assert result.success_count == 0
        assert result.failed_count == 0
        assert len(result.results) == 0

    @pytest.mark.asyncio
    async def test_download_files_with_invalid_urls(self, temp_dir):
        """Test downloading with invalid URLs."""
        urls = [
            "not-a-valid-url",
            "also-invalid",
        ]

        result = await download_files(urls=urls, output_dir=str(temp_dir))

        assert result.success_count == 0
        assert result.failed_count == 2
        assert len(result.results) == 2

        # All should have failed
        for res in result.results:
            assert res.success is False
            assert "Invalid URL format" in res.error


class TestDownloadSingleFile:
    """Tests for download_single_file function."""

    @pytest.mark.asyncio
    async def test_download_single_file_invalid_url(self):
        """Test download_single_file with invalid URL."""
        result = await download_single_file(url="invalid-url")

        assert result.success is False
        assert result.error is not None
        assert "Invalid URL format" in result.error

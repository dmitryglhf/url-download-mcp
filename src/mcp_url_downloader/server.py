import asyncio
import ipaddress
import re
import socket
import urllib.parse
import uuid
from pathlib import Path
from typing import Annotated

import httpx
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

load_dotenv()

# Configuration
MAX_FILE_SIZE_MB = 500
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024
DEFAULT_DOWNLOAD_DIR = Path.home() / "Downloads" / "mcp_downloads"
MAX_CONCURRENT_DOWNLOADS = 10
MAX_URLS_PER_REQUEST = 100
MAX_URL_LENGTH = 2048

# Security: Allowed base directories for downloads
ALLOWED_BASE_DIRS = [
    Path.home() / "Downloads",
    Path.home() / "Documents",
    Path.home() / "Desktop",
    Path("/tmp"),
]

# Security: Blocked IP ranges for SSRF protection
BLOCKED_IP_RANGES = [
    ipaddress.ip_network("127.0.0.0/8"),  # Localhost
    ipaddress.ip_network("10.0.0.0/8"),  # Private
    ipaddress.ip_network("172.16.0.0/12"),  # Private
    ipaddress.ip_network("192.168.0.0/16"),  # Private
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local (AWS metadata)
    ipaddress.ip_network("::1/128"),  # IPv6 localhost
    ipaddress.ip_network("fc00::/7"),  # IPv6 private
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
]

# Security: Allowed MIME types
ALLOWED_CONTENT_TYPES = {
    "application/pdf",
    "application/json",
    "application/xml",
    "application/zip",
    "application/gzip",
    "application/x-tar",
    "application/octet-stream",
    "text/plain",
    "text/html",
    "text/css",
    "text/javascript",
    "text/csv",
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/svg+xml",
    "image/webp",
    "video/mp4",
    "video/mpeg",
    "audio/mpeg",
    "audio/wav",
}

DESCRIPTION = """
MCP server that enables AI assistants to download files from URLs to the local filesystem.

Available tools:
- Download one or more files from URLs and save to local filesystem
- Download a single file from URL with custom filename

Features:
- File size validation (max 500MB by default)
- Automatic filename sanitization
- Collision handling (unique filenames)
- Async downloads for better performance
- SSRF protection (blocks private IPs and localhost)
- Path traversal protection

Example use cases:
- Downloading documents, images, or other files from web URLs
- Batch downloading multiple files
- Saving web content for offline processing
"""

mcp = FastMCP("download-server", instructions=DESCRIPTION)


class DownloadResult(BaseModel):
    """Download result model with file information"""

    file_path: str = Field(..., description="Full path where the file was saved")
    file_name: str = Field(..., description="Name of the downloaded file")
    file_size: int = Field(..., description="Size of the downloaded file in bytes")
    content_type: str | None = Field(None, description="MIME type of the downloaded file")
    success: bool = Field(..., description="Whether the download was successful")
    error: str | None = Field(None, description="Error message if download failed")


class DownloadResponse(BaseModel):
    """Response model for download operations"""

    results: list[DownloadResult] = Field(..., description="List of download results")
    success_count: int = Field(..., description="Number of successful downloads")
    failed_count: int = Field(..., description="Number of failed downloads")


def _validate_output_dir(output_dir: str) -> Path:
    """Validate output directory is within allowed paths.

    Args:
        output_dir: Directory path to validate

    Returns:
        Validated and resolved Path object

    Raises:
        ValueError: If directory is outside allowed locations
    """
    output_path = Path(output_dir).resolve()

    # Check if within allowed directories
    for allowed_dir in ALLOWED_BASE_DIRS:
        try:
            output_path.relative_to(allowed_dir.resolve())
            return output_path
        except ValueError:
            continue

    allowed_dirs_str = ", ".join(str(d) for d in ALLOWED_BASE_DIRS)
    raise ValueError(f"Output directory must be within allowed locations: {allowed_dirs_str}")


def _validate_url_safe(url: str) -> None:
    """Validate URL is safe from SSRF attacks.

    Args:
        url: URL to validate

    Raises:
        ValueError: If URL is unsafe (localhost, private IP, etc.)
    """
    # Validate URL length
    if len(url) > MAX_URL_LENGTH:
        raise ValueError(f"URL too long (max {MAX_URL_LENGTH} characters)")

    parsed = urllib.parse.urlparse(url)

    # Only allow http/https
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported protocol: {parsed.scheme}")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Invalid URL: no hostname")

    # Block localhost variations
    localhost_names = ("localhost", "127.0.0.1", "0.0.0.0", "[::1]", "::1")
    if hostname.lower() in localhost_names:
        raise ValueError("Access to localhost is not allowed")

    # Resolve hostname to IP and check against blocklist
    try:
        addrs = socket.getaddrinfo(hostname, None)
        for addr in addrs:
            ip = ipaddress.ip_address(addr[4][0])
            for blocked_range in BLOCKED_IP_RANGES:
                if ip in blocked_range:
                    raise ValueError(
                        f"Access to {hostname} ({ip}) is blocked (private/internal network)"
                    )
    except socket.gaierror as e:
        raise ValueError(f"Cannot resolve hostname: {hostname}") from e


def _sanitize_error(error: Exception) -> str:
    """Return user-safe error message.

    Args:
        error: Exception to sanitize

    Returns:
        Safe error message for user
    """
    error_str = str(error)

    # Remove file paths
    error_str = re.sub(r"/[\w/.-]+", "[PATH]", error_str)
    error_str = re.sub(r"[A-Z]:\\[\w\\.-]+", "[PATH]", error_str)

    # Map to generic messages for common errors
    if isinstance(error, httpx.HTTPStatusError):
        status = error.response.status_code
        return f"HTTP error: {status}"
    elif isinstance(error, httpx.TimeoutException):
        return "Download timeout exceeded"
    elif isinstance(error, httpx.ConnectError):
        return "Connection failed"
    elif isinstance(error, ValueError):
        return error_str  # Our validation errors are safe
    else:
        return "Download failed"


def _sanitize_filename(filename: str) -> str:
    """Sanitize filename by removing unsafe characters.

    Args:
        filename: Original filename

    Returns:
        Sanitized filename safe for filesystem
    """
    # Remove path separators and other dangerous characters
    # Keep alphanumeric, dots, hyphens, underscores
    sanitized = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", filename)

    # Remove leading/trailing dots and spaces
    sanitized = sanitized.strip(". ")

    # Ensure filename is not empty
    if not sanitized:
        sanitized = "downloaded_file"

    # Limit filename length (255 is common filesystem limit)
    if len(sanitized) > 255:
        name, ext = Path(sanitized).stem, Path(sanitized).suffix
        max_name_len = 255 - len(ext)
        sanitized = name[:max_name_len] + ext

    return sanitized


def _extract_filename_from_url(url: str) -> str:
    """Extract filename from URL.

    Args:
        url: URL to extract filename from

    Returns:
        Extracted and sanitized filename
    """
    try:
        parsed_url = urllib.parse.urlparse(url)
        # Get path and remove query parameters
        path = parsed_url.path
        filename = Path(path).name

        # Decode URL-encoded characters
        filename = urllib.parse.unquote(filename)

        if not filename:
            # Try to get from query parameters (e.g., ?file=name.pdf)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            for key in ["file", "filename", "name"]:
                if key in query_params:
                    filename = query_params[key][0]
                    break

        if not filename:
            filename = "downloaded_file"

        # Ensure it has an extension
        if "." not in filename:
            filename = f"{filename}.bin"

        return _sanitize_filename(filename)

    except Exception:
        return "downloaded_file.bin"


def _get_unique_filepath(file_path: Path) -> Path:
    """Get unique filepath by adding UUID if file exists.

    Args:
        file_path: Original file path

    Returns:
        Unique file path
    """
    if not file_path.exists():
        return file_path

    stem = file_path.stem
    suffix = file_path.suffix
    parent = file_path.parent

    # Use UUID for guaranteed uniqueness (prevents race conditions)
    unique_id = uuid.uuid4().hex[:8]
    unique_name = f"{stem}_{unique_id}{suffix}"
    return parent / unique_name


async def _download_single_file_internal(
    url: str,
    output_dir: str,
    filename: str | None,
    timeout: int,
    max_size_mb: int,
) -> DownloadResult:
    """Internal async function to download a single file.

    Args:
        url: URL to download from
        output_dir: Directory to save file
        filename: Optional custom filename
        timeout: Download timeout in seconds
        max_size_mb: Maximum file size in MB

    Returns:
        DownloadResult with download information
    """
    file_path = None
    try:
        # Validate URL for SSRF
        _validate_url_safe(url)

        # Validate and resolve output directory
        output_path = _validate_output_dir(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        # Determine filename
        if not filename:
            filename = _extract_filename_from_url(url)
        else:
            filename = _sanitize_filename(filename)

        # Get unique filepath to avoid collisions
        file_path = _get_unique_filepath(output_path / filename)
        final_filename = file_path.name

        max_size_bytes = max_size_mb * 1024 * 1024

        # Headers for better compatibility
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
        }

        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            # First, do a HEAD request to check size
            try:
                head_response = await client.head(url, headers=headers)
                content_length = head_response.headers.get("Content-Length")

                if content_length:
                    size = int(content_length)
                    if size > max_size_bytes:
                        size_mb = size / (1024 * 1024)
                        raise ValueError(
                            f"File size ({size_mb:.2f} MB) exceeds "
                            f"maximum allowed size ({max_size_mb} MB)"
                        )
            except httpx.HTTPStatusError:
                # HEAD request not supported, continue with GET
                pass

            # Download the file
            async with client.stream("GET", url, headers=headers) as response:
                response.raise_for_status()

                content_type = response.headers.get("Content-Type", "").split(";")[0]
                downloaded = 0

                # Validate MIME type if present
                if content_type and content_type not in ALLOWED_CONTENT_TYPES:
                    raise ValueError(f"File type not allowed: {content_type}")

                # Write to file
                with open(file_path, "wb") as f:
                    async for chunk in response.aiter_bytes(chunk_size=8192):
                        downloaded += len(chunk)

                        # Check size during download
                        if downloaded > max_size_bytes:
                            # Delete partial file
                            if file_path.exists():
                                file_path.unlink()
                            size_mb = downloaded / (1024 * 1024)
                            raise ValueError(
                                f"File exceeded size limit during download "
                                f"({size_mb:.2f} MB > {max_size_mb} MB)"
                            )

                        f.write(chunk)

                # Verify file was created
                if not file_path.exists():
                    raise ValueError("File was not created")

                actual_size = file_path.stat().st_size

                return DownloadResult(
                    file_path=str(file_path),
                    file_name=final_filename,
                    file_size=actual_size,
                    content_type=content_type,
                    success=True,
                    error=None,
                )

    except Exception as e:
        # Clean up partial file if exists
        if file_path and file_path.exists():
            try:
                file_path.unlink()
            except Exception:
                pass  # Best effort cleanup

        return DownloadResult(
            file_path="",
            file_name=filename or "",
            file_size=0,
            content_type=None,
            success=False,
            error=_sanitize_error(e),
        )


@mcp.tool(description="Download multiple files from URLs and save to local filesystem.")
async def download_files(
    urls: Annotated[list[str], Field(description="List of URLs to download")],
    output_dir: Annotated[
        str | None, Field(description="Directory to save downloaded files")
    ] = None,
    timeout: Annotated[int, Field(description="Download timeout in seconds", ge=1, le=300)] = 60,
    max_size_mb: Annotated[
        int, Field(description="Maximum file size in MB (default: 500)", ge=1, le=5000)
    ] = MAX_FILE_SIZE_MB,
) -> DownloadResponse:
    """Download files from URLs and save to the local filesystem.

    Args:
        urls: List of URLs to download
        output_dir: Directory to save the files (defaults to ~/Downloads/mcp_downloads)
        timeout: Download timeout in seconds (1-300)
        max_size_mb: Maximum file size in MB (1-5000)

    Returns:
        DownloadResponse with results for each file
    """
    if output_dir is None:
        output_dir = str(DEFAULT_DOWNLOAD_DIR)

    # Limit number of URLs per request
    if len(urls) > MAX_URLS_PER_REQUEST:
        raise ValueError(f"Maximum {MAX_URLS_PER_REQUEST} URLs per request")

    # Use semaphore to limit concurrent downloads
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_DOWNLOADS)

    async def download_with_limit(url: str) -> DownloadResult:
        async with semaphore:
            return await _download_single_file_internal(url, output_dir, None, timeout, max_size_mb)

    # Download all files with concurrency limit
    tasks = [download_with_limit(url) for url in urls]
    results = await asyncio.gather(*tasks, return_exceptions=False)

    success_count = sum(1 for r in results if r.success)
    failed_count = len(results) - success_count

    return DownloadResponse(results=results, success_count=success_count, failed_count=failed_count)


@mcp.tool(description="Download a single file from URL with optional custom filename.")
async def download_single_file(
    url: Annotated[str, Field(description="URL of the file to download")],
    output_dir: Annotated[str | None, Field(description="Directory to save the file")] = None,
    filename: Annotated[str | None, Field(description="Custom filename (optional)")] = None,
    timeout: Annotated[int, Field(description="Download timeout in seconds", ge=1, le=300)] = 60,
    max_size_mb: Annotated[
        int, Field(description="Maximum file size in MB (default: 500)", ge=1, le=5000)
    ] = MAX_FILE_SIZE_MB,
) -> DownloadResult:
    """Download a single file from URL and save to the local filesystem.

    Args:
        url: URL of the file to download
        output_dir: Directory to save the file (defaults to ~/Downloads/mcp_downloads)
        filename: Custom filename (if not provided, extracted from URL)
        timeout: Download timeout in seconds (1-300)
        max_size_mb: Maximum file size in MB (1-5000)

    Returns:
        DownloadResult with download information
    """
    if output_dir is None:
        output_dir = str(DEFAULT_DOWNLOAD_DIR)

    return await _download_single_file_internal(url, output_dir, filename, timeout, max_size_mb)


def main():
    """Main entry point for the MCP URL Downloader server."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()

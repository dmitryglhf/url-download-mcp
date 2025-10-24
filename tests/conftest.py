"""Pytest configuration and fixtures for MCP URL Downloader tests."""

import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test downloads."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_file_content():
    """Sample file content for testing."""
    return b"This is a test file content. " * 100


@pytest.fixture
def mock_response_headers():
    """Mock HTTP response headers."""
    return {
        "Content-Type": "application/pdf",
        "Content-Length": "1024",
    }

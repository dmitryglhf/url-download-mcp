# MCP URL Downloader

A Model Context Protocol (MCP) server that enables AI assistants to download files from URLs to the local filesystem.

## Features

- Download single or multiple files from URLs
- File size validation (configurable, default 500MB)
- Automatic filename sanitization
- Unique filename generation to prevent overwrites
- Concurrent downloads with limits
- **Security**: SSRF protection, path traversal protection, MIME type validation

## Installation

```bash
# Using uvx (recommended)
uvx mcp-url-downloader

# Using pip
pip install mcp-url-downloader

# From source
git clone https://github.com/dmitryglhf/mcp-url-downloader.git
cd mcp-url-downloader
uv sync
```

## Configuration

### Claude Desktop

Add to your configuration file:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "url-downloader": {
      "command": "uvx",
      "args": ["mcp-url-downloader"]
    }
  }
}
```

## Usage

### `download_files`
Download multiple files from URLs.

### `download_single_file`
Download a single file with optional custom filename.

### Rate Limits

- Maximum 100 URLs per `download_files` request
- Maximum 10 concurrent downloads
- URL length limited to 2048 characters
- Timeout range: 1-300 seconds
- File size range: 1-5000 MB

## Development

```bash
# Run tests
uv run pytest

```

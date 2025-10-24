# MCP URL Downloader

A Model Context Protocol (MCP) server that enables AI assistants to download files from URLs to the local filesystem.

## Features

- Download single or multiple files from URLs with concurrent support
- File size validation (configurable, default 500MB)
- Unique filename generation to prevent overwrites
- Security

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

To integrate server with Claude, add the following to your `claude_desktop_config.json` file:

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
## Tools

### `download_single_file`
Download a single file from a URL with optional custom filename.

**Parameters:**
- `url` (string, required): URL of the file to download
  - Must be a valid HTTP/HTTPS URL
  - Maximum length: 2048 characters
- `output_dir` (string, optional): Directory to save the file
  - Default: `~/Downloads/mcp-downloads/`
  - Must be a valid writable directory path
- `filename` (string, optional): Custom filename for the saved file
  - If not provided, extracted from URL
  - Will be sanitized automatically
  - Extension will be preserved or detected
- `timeout` (number, optional): Download timeout in seconds
  - Default: `60`
  - Range: `1-300`
- `max_size_mb` (number, optional): Maximum file size in MB
  - Default: `500`
  - Range: `1-5000`

### `download_files`
Download multiple files from URLs concurrently.

**Parameters:**
- `urls` (array of strings, required): List of URLs to download
  - Each URL must be valid HTTP/HTTPS
  - Maximum: 100 URLs per request
  - Each URL max length: 2048 characters
- `output_dir` (string, optional): Directory to save all files
  - Default: `~/Downloads/mcp-downloads/`
  - All files will be saved to this directory
- `timeout` (number, optional): Download timeout in seconds per file
  - Default: `60`
  - Range: `1-300`
- `max_size_mb` (number, optional): Maximum file size in MB per file
  - Default: `500`
  - Range: `1-5000`


### Rate Limits

- Maximum 100 URLs per `download_files` request
- Maximum concurrent downloads: 10 (configurable up to 50)
- URL length limited to 2048 characters
- Timeout range: 1-300 seconds
- File size range: 1-5000 MB


## Development

```bash
# Run tests
uv run pytest
```

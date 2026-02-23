"""
Read-only MCP tools - Safe operations that don't modify system state.
Implements: read_file, grep_search, fetch_docs
"""

import logging
import os
import re
from typing import Optional

import aiohttp

from backend.shared.security import SecurityGuard
from backend.mcp_tools.tool_schemas import (
    ReadFileArgs, GrepSearchArgs, FetchDocsArgs, pydantic_to_input_schema,
)

logger = logging.getLogger(__name__)


class ReadFileTool:
    """Safely read a file within PROJECT_ROOT."""

    def __init__(self, security: SecurityGuard, project_root: str):
        self._security = security
        self._project_root = project_root
        self._max_size = security._config.max_file_size_bytes

    async def execute(self, path: str) -> dict:
        path = self._security.sanitize_input(path)
        if not self._security.validate_path(path):
            return {"success": False, "error": "Path validation failed"}

        full_path = os.path.join(self._project_root, path)
        if not os.path.isfile(full_path):
            return {"success": False, "error": f"File not found: {path}"}

        size = os.path.getsize(full_path)
        if size > self._max_size:
            return {
                "success": False,
                "error": f"File too large: {size} bytes (max {self._max_size})",
            }

        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            return {"success": True, "output": content}
        except Exception as e:
            logger.error(f"read_file error: {e}")
            return {"success": False, "error": str(e)}

    @staticmethod
    def definition() -> dict:
        return {
            "name": "read_file",
            "description": "Read contents of a file within the project root.",
            "input_schema": pydantic_to_input_schema(ReadFileArgs),
        }


class GrepSearchTool:
    """Search files using regex within PROJECT_ROOT."""

    def __init__(self, security: SecurityGuard, project_root: str):
        self._security = security
        self._project_root = project_root
        self._max_results = security._config.max_grep_results

    async def execute(self, query: str, path: str = ".") -> dict:
        query = self._security.sanitize_input(query)
        if not self._security.validate_path(path):
            return {"success": False, "error": "Path validation failed"}

        search_path = os.path.join(self._project_root, path)
        if not os.path.exists(search_path):
            return {"success": False, "error": f"Path not found: {path}"}

        try:
            pattern = re.compile(query, re.IGNORECASE)
        except re.error as e:
            return {"success": False, "error": f"Invalid regex: {e}"}

        results = []
        try:
            for root, _, files in os.walk(search_path):
                if len(results) >= self._max_results:
                    break
                for fname in files:
                    if len(results) >= self._max_results:
                        break
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                            for i, line in enumerate(f, 1):
                                if pattern.search(line):
                                    rel = os.path.relpath(fpath, self._project_root)
                                    results.append(f"{rel}:{i}: {line.rstrip()}")
                                    if len(results) >= self._max_results:
                                        break
                    except (OSError, UnicodeDecodeError):
                        continue

            return {"success": True, "output": "\n".join(results)}
        except Exception as e:
            logger.error(f"grep_search error: {e}")
            return {"success": False, "error": str(e)}

    @staticmethod
    def definition() -> dict:
        return {
            "name": "grep_search",
            "description": "Search for a regex pattern across project files.",
            "input_schema": pydantic_to_input_schema(GrepSearchArgs),
        }


class FetchDocsTool:
    """Fetch documentation from allow-listed domains."""

    def __init__(self, security: SecurityGuard):
        self._security = security

    async def execute(self, url: str) -> dict:
        if not self._security.validate_url(url):
            return {"success": False, "error": "URL not in allow-list"}

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status != 200:
                        return {"success": False, "error": f"HTTP {resp.status}"}
                    text = await resp.text()
                    # Truncate to prevent token overflow
                    return {"success": True, "output": text[:10000]}
        except Exception as e:
            logger.error(f"fetch_docs error: {e}")
            return {"success": False, "error": str(e)}

    @staticmethod
    def definition() -> dict:
        return {
            "name": "fetch_docs",
            "description": "Fetch documentation from approved domains.",
            "input_schema": pydantic_to_input_schema(FetchDocsArgs),
        }

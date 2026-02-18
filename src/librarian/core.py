"""Core logic helpers for Librarian."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


DOCUMENT_KEY = "document"
INVENTORY_KEY = "inventory"

REQUIRED_HEADER_KEYS = ["document-id"]
RECOMMENDED_HEADER_KEYS = ["title", "purpose"]


@dataclass
class ParseResult:
    obj: Any | None
    error: str | None


def parse_json_text(text: str) -> ParseResult:
    """Parse JSON text into an object."""
    try:
        return ParseResult(json.loads(text), None)
    except json.JSONDecodeError as exc:
        return ParseResult(None, f"invalid JSON at line {exc.lineno} column {exc.colno}: {exc.msg}")


def load_json_file(path: str | Path) -> ParseResult:
    """Load a JSON file; return object or a human-friendly error."""
    try:
        raw = Path(path).read_bytes()
    except FileNotFoundError:
        return ParseResult(None, "file not found")
    except OSError as exc:
        return ParseResult(None, str(exc))

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("utf-8", errors="replace")

    return parse_json_text(text)


def ensure_top_level_object(obj: Any) -> ParseResult:
    """Validate that the top-level JSON value is an object."""
    if isinstance(obj, dict):
        return ParseResult(obj, None)
    return ParseResult(None, "top-level JSON value must be an object")


def extract_header(doc_obj: dict[str, Any]) -> dict[str, Any] | None:
    """Return the document header object if present and valid."""
    header = doc_obj.get(DOCUMENT_KEY)
    if isinstance(header, dict):
        return header
    return None


def normalize_header(header_obj: dict[str, Any] | None) -> dict[str, Any]:
    """Ensure required/recommended keys exist with empty-string defaults.

    Remaps legacy ``document_id`` to the canonical ``document-id`` key.
    """
    if header_obj is None:
        header_obj = {}
    if not isinstance(header_obj, dict):
        raise ValueError("document header must be a JSON object")

    # Accept legacy underscore form; always output canonical hyphenated form.
    if "document_id" in header_obj:
        if "document-id" not in header_obj:
            header_obj["document-id"] = header_obj.pop("document_id")
        else:
            del header_obj["document_id"]

    for key in REQUIRED_HEADER_KEYS + RECOMMENDED_HEADER_KEYS:
        if key not in header_obj:
            header_obj[key] = ""
    return header_obj


def is_valid_document_id(value: Any) -> bool:
    return isinstance(value, str) and value.strip() != ""


def validate_header_required(header_obj: dict[str, Any]) -> ParseResult:
    """Validate required header keys; returns ParseResult with error when invalid."""
    doc_id = header_obj.get("document-id")
    if not is_valid_document_id(doc_id):
        return ParseResult(None, "document-id missing or empty")
    return ParseResult(header_obj, None)


def format_json(obj: Any, compressed: bool) -> str:
    if compressed:
        return json.dumps(obj, separators=(",", ":"), ensure_ascii=False) + "\n"
    return json.dumps(obj, indent=2, ensure_ascii=False) + "\n"


def atomic_write_text(path: str | Path, text: str) -> None:
    """Write text to a file atomically (best-effort on Windows)."""
    path = Path(path)
    directory = path.parent
    directory.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=path.name, dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
        os.replace(tmp_path, path)
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass


def update_document_header(doc_obj: dict[str, Any], header_obj: dict[str, Any]) -> dict[str, Any]:
    """Insert or replace the top-level document header in a document object."""
    new_obj: dict[str, Any] = {DOCUMENT_KEY: header_obj}
    for key, value in doc_obj.items():
        if key == DOCUMENT_KEY:
            continue
        new_obj[key] = value
    return new_obj


def ensure_inventory_obj(inv_obj: dict[str, Any] | None) -> dict[str, Any]:
    if inv_obj is None:
        return {INVENTORY_KEY: {}}
    if INVENTORY_KEY not in inv_obj or not isinstance(inv_obj[INVENTORY_KEY], dict):
        inv_obj = dict(inv_obj)
        inv_obj[INVENTORY_KEY] = {}
    return inv_obj


def update_inventory_entry(
    inv_obj: dict[str, Any] | None,
    document_id: str,
    filepath: str,
    title: str | None,
    purpose: str | None,
) -> dict[str, Any]:
    """Return inventory object updated with the given document data."""
    inv_obj = ensure_inventory_obj(inv_obj)
    entry: dict[str, Any] = {
        "document-id": document_id,
        "filepath": filepath,
    }
    if title is not None:
        entry["title"] = title
    if purpose is not None:
        entry["purpose"] = purpose
    inv_obj[INVENTORY_KEY][document_id] = entry
    return inv_obj


def _sorted_entries(path: Path) -> list[Path]:
    dirs: list[Path] = []
    files: list[Path] = []
    try:
        for entry in path.iterdir():
            if entry.is_dir():
                dirs.append(entry)
            else:
                files.append(entry)
    except OSError:
        return []

    dirs.sort(key=lambda p: p.name.lower())
    files.sort(key=lambda p: p.name.lower())
    return dirs + files


def build_tree_lines(
    root: str | Path,
    depth_limit: int = 4,
    include_files: bool = True,
    include_dirs: bool = True,
) -> list[str]:
    """Build an ASCII tree for the directory rooted at `root`."""
    root = Path(root)
    lines: list[str] = [root.name + ("/" if root.is_dir() else "")]

    def walk(current: Path, prefix: str, depth: int) -> None:
        if depth >= depth_limit:
            return
        entries = _sorted_entries(current)
        for i, entry in enumerate(entries):
            is_last = i == len(entries) - 1
            branch = "`-- " if is_last else "|-- "
            next_prefix = prefix + ("    " if is_last else "|   ")
            if entry.is_dir():
                if include_dirs:
                    lines.append(prefix + branch + entry.name + "/")
                walk(entry, next_prefix, depth + 1)
            else:
                if include_files:
                    lines.append(prefix + branch + entry.name)

    if root.is_dir():
        walk(root, "", 0)
    return lines


def build_tree_text(
    root: str | Path,
    depth_limit: int = 4,
    include_files: bool = True,
    include_dirs: bool = True,
) -> str:
    return "\n".join(build_tree_lines(root, depth_limit, include_files, include_dirs))


def build_tree_compressed(
    root: str | Path,
    depth_limit: int = 3,
    max_entries: int = 200,
) -> str:
    root = Path(root)
    root_name = root.name
    lines: list[str] = []

    def walk(current: Path, depth: int, rel_prefix: str) -> None:
        if depth >= depth_limit:
            return
        for entry in _sorted_entries(current):
            rel_path = f"{rel_prefix}{entry.name}"
            if entry.is_dir():
                lines.append(rel_path + "/")
                walk(entry, depth + 1, rel_path + "/")
            else:
                lines.append(rel_path)

    if root.is_dir():
        walk(root, 0, f"{root_name}/")
    else:
        lines.append(root_name)

    if len(lines) > max_entries:
        remaining = len(lines) - max_entries
        lines = lines[:max_entries]
        lines.append(f"... ({remaining} more)")
    return "\n".join(lines)


def derive_inventory_fields(
    header_obj: dict[str, Any],
    filepath: str,
) -> dict[str, Any]:
    """Derive inventory fields from a header object."""
    return {
        "document-id": header_obj.get("document-id", ""),
        "filepath": filepath,
        "title": header_obj.get("title"),
        "purpose": header_obj.get("purpose"),
    }

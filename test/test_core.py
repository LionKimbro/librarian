import json
from pathlib import Path

import librarian.core as core


def test_parse_json_text_invalid():
    result = core.parse_json_text("{bad}")
    assert result.obj is None
    assert result.error is not None


def test_parse_json_text_valid():
    result = core.parse_json_text('{"a": 1}')
    assert result.error is None
    assert result.obj == {"a": 1}


def test_ensure_top_level_object():
    ok = core.ensure_top_level_object({"a": 1})
    assert ok.error is None
    assert ok.obj == {"a": 1}

    bad = core.ensure_top_level_object([1, 2])
    assert bad.obj is None
    assert bad.error == "top-level JSON value must be an object"


def test_extract_and_normalize_header():
    # Input uses legacy document_id key; should be remapped to document-id.
    doc = {"document": {"document_id": "abc"}}
    header = core.extract_header(doc)
    normalized = core.normalize_header(header)
    assert normalized["document-id"] == "abc"
    assert "document_id" not in normalized
    assert "title" in normalized
    assert "purpose" in normalized

    normalized2 = core.normalize_header(None)
    assert normalized2["document-id"] == ""


def test_validate_header_required():
    bad = core.validate_header_required({"document-id": ""})
    assert bad.error == "document-id missing or empty"

    ok = core.validate_header_required({"document-id": "x"})
    assert ok.error is None


def test_format_json_pretty_and_compact():
    obj = {"a": 1}
    pretty = core.format_json(obj, compressed=False)
    compact = core.format_json(obj, compressed=True)
    assert pretty.endswith("\n")
    assert compact.endswith("\n")
    assert "\n" in pretty
    assert compact.strip() == json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def test_update_document_header():
    doc = {"x": 1, "y": 2}
    header = {"document-id": "d"}
    updated = core.update_document_header(doc, header)
    assert updated["x"] == 1
    assert updated["document"] == header
    assert list(updated.keys())[0] == "document"
    assert list(updated.keys())[1:] == ["x", "y"]


def test_update_inventory_entry():
    inv = core.update_inventory_entry(None, "doc1", "path.json", "Title", "Purpose")
    assert "inventory" in inv
    assert inv["inventory"]["doc1"]["filepath"] == "path.json"


def test_build_tree_lines_and_compressed(tmp_path: Path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "file.txt").write_text("x", encoding="utf-8")
    (tmp_path / "b.txt").write_text("y", encoding="utf-8")

    lines = core.build_tree_lines(tmp_path, depth_limit=4)
    assert lines[0].endswith("/")
    assert any("file.txt" in line for line in lines)

    compressed = core.build_tree_compressed(tmp_path, depth_limit=2)
    assert "file.txt" in compressed


def test_atomic_write_text(tmp_path: Path):
    path = tmp_path / "out.txt"
    core.atomic_write_text(path, "hello\n")
    assert path.read_text(encoding="utf-8") == "hello\n"

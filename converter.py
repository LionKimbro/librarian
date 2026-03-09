#!/usr/bin/env python3
"""Convert a Librarian1 inventory.json to a Librarian2 registry JSON."""

import json
import sys
from pathlib import Path


def convert(input_path: str, output_path: str) -> None:
    src = Path(input_path)
    data = json.loads(src.read_text(encoding="utf-8"))

    inventory = data.get("inventory", {})

    registry = {}
    for doc_id, entry in inventory.items():
        resource_id = entry.get("document-id", doc_id)
        filepath = entry.get("filepath")
        title = entry.get("title")
        purpose = entry.get("purpose", "")

        resource = {"id": resource_id}
        if title is not None:
            resource["title"] = title
        resource["purpose"] = purpose
        if filepath:
            resource["location"] = [{"path": filepath}]
        resource["type"] = {
            "logical": {"base": "file", "format": "json"},
            "semantic": {"base": "document"},
        }
        registry[resource_id] = resource

    out = {
        "document": {
            "document-id": f"registry.{src.stem}",
            "title": f"Registry (converted from {src.name})",
            "purpose": f"Resource registry converted from Librarian1 inventory {src.name}.",
        },
        "registry": registry,
    }

    text = json.dumps(out, indent=2, ensure_ascii=False) + "\n"
    Path(output_path).write_text(text, encoding="utf-8")
    print(f"Converted {len(registry)} entries to {output_path}")


def main() -> None:
    if len(sys.argv) != 3:
        print(
            f"Usage: {sys.argv[0]} <input-librarian1.json> <output-librarian2.json>",
            file=sys.stderr,
        )
        sys.exit(1)
    convert(sys.argv[1], sys.argv[2])


if __name__ == "__main__":
    main()

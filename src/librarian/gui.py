"""Tkinter GUI for Librarian."""

from __future__ import annotations

import json
import shutil
import shlex
import subprocess
from pathlib import Path
from typing import Any

import pyperclip
import tkinter as tk
from tkinter import filedialog

from . import core

try:
    import lionscliapp as app
except Exception:  # pragma: no cover - optional for direct execution
    app = None


VALIDATION_INTERVAL_MS = 750

APP_G: dict[str, Any] | None = None
APP_WINDOW: tk.Misc | None = None


def _ctx_value(key: str, default: Any) -> Any:
    if app is None:
        return default
    try:
        return app.ctx.get(key, default)
    except Exception:
        return default


def get_app_state() -> dict[str, Any] | None:
    return APP_G


def _create_state() -> dict[str, Any]:
    return {
        "path_entry_value": "",
        "loaded_path": None,
        "loaded_doc_obj": None,
        "loaded_doc_json_error": None,
        "loaded_header_obj": None,
        "header_text_last_valid_obj": None,
        "header_text_last_error": None,
        "save_compressed": False,
        "inventory_obj": None,
        "loaded_disk_header_valid": False,
    }


def create_app(window: tk.Misc, root: tk.Misc | None = None) -> dict[str, Any]:
    g = _create_state()
    g["root"] = root or window
    g["window"] = window
    g["path_inventory"] = _ctx_value("path.inventory", "inventory.json")
    g["path_jsonedit"] = _ctx_value("path.jsonedit", "jsonedit")
    _build_ui(window, g)
    return g


def app_entry() -> None:
    global APP_G, APP_WINDOW

    root = tk._default_root
    created_root = False
    if root is None:
        root = tk.Tk()
        created_root = True

    window = root if created_root else tk.Toplevel(root)
    APP_G = create_app(window, root=root)
    APP_WINDOW = window


def app_exit() -> None:
    global APP_G, APP_WINDOW

    if APP_WINDOW is not None:
        try:
            APP_WINDOW.destroy()
        except Exception:
            pass
    if APP_G is not None:
        after_id = APP_G.get("validation_after_id")
        if after_id and APP_G.get("root") is not None:
            try:
                APP_G["root"].after_cancel(after_id)
            except Exception:
                pass
    APP_WINDOW = None
    APP_G = None


def gui_main() -> None:
    """Launch the Librarian GUI."""
    global APP_G, APP_WINDOW

    root = tk.Tk()
    APP_G = create_app(root, root=root)
    APP_WINDOW = root
    root.mainloop()


def _build_ui(window: tk.Misc, g: dict[str, Any]) -> None:
    window.title("Librarian")
    try:
        window.minsize(900, 650)
    except Exception:
        pass

    path_inventory = g["path_inventory"]
    path_jsonedit = g["path_jsonedit"]

    path_var = tk.StringVar(value="")
    save_compressed_var = tk.BooleanVar(value=False)

    # Layout frames
    top_frame = tk.Frame(window)
    top_frame.pack(side=tk.TOP, fill=tk.X, padx=8, pady=6)

    indicators_frame = tk.Frame(window)
    indicators_frame.pack(side=tk.TOP, fill=tk.X, padx=8, pady=2)

    status_frame = tk.Frame(window)
    status_frame.pack(side=tk.TOP, fill=tk.X, padx=8, pady=2)

    body_frame = tk.Frame(window)
    body_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=8, pady=6)

    left_frame = tk.Frame(body_frame)
    left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8))

    right_frame = tk.Frame(body_frame, width=200)
    right_frame.pack(side=tk.RIGHT, fill=tk.Y)

    # Path row
    tk.Label(top_frame, text="Path:").pack(side=tk.LEFT)
    path_entry = tk.Entry(top_frame, textvariable=path_var, width=80)
    path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=6)

    def _set_indicators(json_state: str, header_state: str) -> None:
        json_indicator.config(text=json_state)
        header_indicator.config(text=header_state)

    def _set_status(text: str) -> None:
        status_var.set(text)

    def _set_header_text(text: str) -> None:
        header_text.delete("1.0", tk.END)
        header_text.insert("1.0", text)

    def _update_copy_buttons_state() -> None:
        enabled = bool(path_var.get().strip())
        state = tk.NORMAL if enabled else tk.DISABLED
        copy_path_button.config(state=state)
        copy_tree_button.config(state=state)
        copy_tree_comp_button.config(state=state)
        jsonedit_button.config(state=state)

    def on_select() -> None:
        filename = filedialog.askopenfilename(
            title="Select JSON document",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if filename:
            path_var.set(filename)
            g["path_entry_value"] = filename
            _update_copy_buttons_state()
            on_load()

    select_button = tk.Button(top_frame, text="Select", command=on_select)
    select_button.pack(side=tk.LEFT, padx=2)

    def on_load() -> None:
        path = path_var.get().strip()
        g["path_entry_value"] = path
        if not path:
            _set_status("NOT LOADED. Select a file or paste a path, then click Load.")
            _set_indicators("NOT_LOADED", "NOT_LOADED")
            return
        result = core.load_json_file(path)
        if result.error:
            g["loaded_doc_obj"] = None
            g["loaded_path"] = None
            g["loaded_doc_json_error"] = result.error
            _set_indicators("INVALID", "NOT_LOADED")
            _set_status(f"LOAD FAILED: {result.error}.")
            return
        top_level = core.ensure_top_level_object(result.obj)
        if top_level.error:
            g["loaded_doc_obj"] = None
            g["loaded_path"] = None
            g["loaded_doc_json_error"] = top_level.error
            _set_indicators("INVALID", "NOT_LOADED")
            _set_status(f"LOAD FAILED: {top_level.error}.")
            return

        g["loaded_doc_obj"] = top_level.obj
        g["loaded_path"] = path
        g["loaded_doc_json_error"] = None

        header = core.extract_header(top_level.obj)
        if header is None:
            header = core.normalize_header(None)
            _set_indicators("VALID", "MISSING")
            _set_status("HEADER MISSING: stub header created (not saved).")
            g["loaded_disk_header_valid"] = False
        else:
            header = core.normalize_header(header)
            _set_indicators("VALID", "PRESENT")
            header_valid = core.validate_header_required(header)
            g["loaded_disk_header_valid"] = header_valid.error is None
            if header_valid.error:
                _set_status("HEADER INVALID: document_id missing or empty.")
            else:
                _set_status("READY: header valid. You may Save or Index.")

        g["loaded_header_obj"] = header
        _set_header_text(json.dumps(header, indent=2, ensure_ascii=False))
        _refresh_inventory_list()
        _update_action_buttons_state()

    load_button = tk.Button(top_frame, text="Load", command=on_load)
    load_button.pack(side=tk.LEFT, padx=2)

    # Indicators row
    tk.Label(indicators_frame, text="JSON:").pack(side=tk.LEFT)
    json_indicator = tk.Label(indicators_frame, text="NOT_LOADED", width=10, anchor="w")
    json_indicator.pack(side=tk.LEFT, padx=(0, 10))

    tk.Label(indicators_frame, text="Header:").pack(side=tk.LEFT)
    header_indicator = tk.Label(indicators_frame, text="NOT_LOADED", width=10, anchor="w")
    header_indicator.pack(side=tk.LEFT, padx=(0, 10))

    # Status
    status_var = tk.StringVar(value="NOT LOADED. Select a file or paste a path, then click Load.")
    status_label = tk.Label(status_frame, textvariable=status_var, anchor="w", justify=tk.LEFT)
    status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)

    # Header editor
    tk.Label(left_frame, text="Document Header").pack(side=tk.TOP, anchor="w")
    header_text = tk.Text(left_frame, wrap=tk.NONE, height=20)
    header_text.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

    # Save format controls
    save_frame = tk.Frame(left_frame)
    save_frame.pack(side=tk.TOP, fill=tk.X, pady=4)
    save_checkbox = tk.Checkbutton(
        save_frame,
        text="Save compressed",
        variable=save_compressed_var,
        command=lambda: _on_save_compressed_change(),
    )
    save_checkbox.pack(side=tk.LEFT)

    # Action buttons (document actions + utilities)
    action_frame = tk.Frame(left_frame)
    action_frame.pack(side=tk.TOP, fill=tk.X, pady=6)
    save_button = tk.Button(action_frame, text="Save to Document", command=lambda: on_save())
    save_button.pack(side=tk.LEFT, padx=(0, 6))
    index_button = tk.Button(action_frame, text="Index Document", command=lambda: on_index())
    index_button.pack(side=tk.LEFT, padx=(0, 12))

    # Inventory view
    tk.Label(right_frame, text="Inventory").pack(side=tk.TOP, anchor="w")
    inventory_list = tk.Listbox(right_frame, width=40)
    inventory_list.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

    # Utility buttons (same row as Save/Index)
    copy_path_button = tk.Button(action_frame, text="Copy Path", command=lambda: on_copy_path())
    copy_path_button.pack(side=tk.LEFT, padx=(0, 6))
    copy_tree_button = tk.Button(action_frame, text="Copy JSON", command=lambda: on_copy_tree(False))
    copy_tree_button.pack(side=tk.LEFT, padx=(0, 6))
    copy_tree_comp_button = tk.Button(
        action_frame, text="Copy JSON (min)", command=lambda: on_copy_tree(True)
    )
    copy_tree_comp_button.pack(side=tk.LEFT, padx=(0, 6))
    jsonedit_button = tk.Button(action_frame, text="JSONEdit", command=lambda: on_jsonedit())
    jsonedit_button.pack(side=tk.LEFT)

    g["widgets"] = {
        "path_entry": path_entry,
        "select_button": select_button,
        "load_button": load_button,
        "json_indicator": json_indicator,
        "header_indicator": header_indicator,
        "status_var": status_var,
        "header_text": header_text,
        "save_checkbox": save_checkbox,
        "save_button": save_button,
        "index_button": index_button,
        "inventory_list": inventory_list,
        "copy_path_button": copy_path_button,
        "copy_tree_button": copy_tree_button,
        "copy_tree_comp_button": copy_tree_comp_button,
        "jsonedit_button": jsonedit_button,
    }

    g["vars"] = {
        "path_var": path_var,
        "save_compressed_var": save_compressed_var,
    }

    g["inventory_ids"] = []

    def _on_save_compressed_change() -> None:
        g["save_compressed"] = bool(save_compressed_var.get())

    def _validate_header_editor() -> None:
        text = header_text.get("1.0", tk.END).strip()
        if not text:
            g["header_text_last_valid_obj"] = None
            g["header_text_last_error"] = "empty"
            _update_action_buttons_state()
            return
        parsed = core.parse_json_text(text)
        if parsed.error:
            g["header_text_last_valid_obj"] = None
            g["header_text_last_error"] = parsed.error
            _set_status(f"HEADER INVALID: {parsed.error}.")
            _update_action_buttons_state()
            return
        if not isinstance(parsed.obj, dict):
            g["header_text_last_valid_obj"] = None
            g["header_text_last_error"] = "header must be a JSON object"
            _set_status("HEADER INVALID: header must be a JSON object.")
            _update_action_buttons_state()
            return

        g["header_text_last_valid_obj"] = parsed.obj
        g["header_text_last_error"] = None

        required = core.validate_header_required(parsed.obj)
        if required.error:
            _set_status("HEADER INVALID: document_id missing or empty.")
        else:
            missing_recommended = [
                key for key in core.RECOMMENDED_HEADER_KEYS if key not in parsed.obj
            ]
            if missing_recommended:
                _set_status("READY: header valid. Recommended keys missing.")
            else:
                _set_status("READY: header valid. You may Save or Index.")

        _update_action_buttons_state()

    def _validate_header_loop() -> None:
        # Stop validation loop if window has been destroyed.
        if not header_text.winfo_exists():
            return
        _validate_header_editor()
        g["validation_after_id"] = g["root"].after(VALIDATION_INTERVAL_MS, _validate_header_loop)

    def _update_action_buttons_state() -> None:
        header_valid = g["header_text_last_valid_obj"] is not None
        doc_id_ok = False
        if header_valid:
            doc_id_ok = core.is_valid_document_id(
                g["header_text_last_valid_obj"].get("document_id")
            )
        save_enabled = bool(g["loaded_doc_obj"]) and header_valid and doc_id_ok
        save_button.config(state=tk.NORMAL if save_enabled else tk.DISABLED)

        index_enabled = bool(g["loaded_doc_obj"]) and g["loaded_disk_header_valid"]
        index_button.config(state=tk.NORMAL if index_enabled else tk.DISABLED)

    def on_save() -> None:
        if not g["loaded_doc_obj"] or not g["loaded_path"]:
            _set_status("NOT LOADED. Select a file or paste a path, then click Load.")
            return
        header_obj = g["header_text_last_valid_obj"]
        if header_obj is None:
            _set_status("HEADER INVALID: cannot save.")
            return
        required = core.validate_header_required(header_obj)
        if required.error:
            _set_status("HEADER INVALID: document_id missing or empty.")
            return

        updated_doc = core.update_document_header(g["loaded_doc_obj"], header_obj)
        formatted = core.format_json(updated_doc, compressed=bool(save_compressed_var.get()))
        core.atomic_write_text(g["loaded_path"], formatted)
        g["loaded_doc_obj"] = updated_doc
        g["loaded_disk_header_valid"] = True
        if save_compressed_var.get():
            _set_status("SAVED: wrote document header to file (compressed).")
        else:
            _set_status("SAVED: wrote document header to file (pretty).")
        _update_action_buttons_state()

    def on_index() -> None:
        if not g["loaded_path"]:
            _set_status("NOT LOADED. Select a file or paste a path, then click Load.")
            return
        doc_result = core.load_json_file(g["loaded_path"])
        if doc_result.error:
            _set_status(f"LOAD FAILED: {doc_result.error}.")
            return
        top_level = core.ensure_top_level_object(doc_result.obj)
        if top_level.error:
            _set_status(f"LOAD FAILED: {top_level.error}.")
            return
        header = core.extract_header(top_level.obj)
        if header is None:
            _set_status("HEADER INVALID: document_id missing or empty.")
            return
        header = core.normalize_header(header)
        required = core.validate_header_required(header)
        if required.error:
            _set_status("HEADER INVALID: document_id missing or empty.")
            return

        inv_path = Path(path_inventory)
        inv_result = core.load_json_file(inv_path)
        inv_obj = None
        if inv_result.error:
            inv_obj = {core.INVENTORY_KEY: {}}
        else:
            inv_top = core.ensure_top_level_object(inv_result.obj)
            inv_obj = inv_top.obj if inv_top.error is None else {core.INVENTORY_KEY: {}}

        inv_obj = core.update_inventory_entry(
            inv_obj,
            header["document_id"],
            str(g["loaded_path"]),
            header.get("title"),
            header.get("purpose"),
        )
        inv_text = core.format_json(inv_obj, compressed=False)
        core.atomic_write_text(inv_path, inv_text)
        g["inventory_obj"] = inv_obj
        _refresh_inventory_list()
        _set_status(f"INDEXED: updated inventory.json entry for {header['document_id']}")

    def on_copy_path() -> None:
        path = path_var.get().strip()
        if not path:
            return
        pyperclip.copy(path)
        _set_status("Copied path to clipboard.")

    def on_copy_tree(compressed: bool) -> None:
        path = path_var.get().strip()
        if not path:
            return
        doc_result = core.load_json_file(path)
        if doc_result.error:
            _set_status(f"LOAD FAILED: {doc_result.error}.")
            return
        if compressed:
            text = json.dumps(doc_result.obj, separators=(",", ":"), ensure_ascii=False) + "\n"
            _set_status("Copied JSON document to clipboard (compressed).")
        else:
            text = json.dumps(doc_result.obj, indent=2, ensure_ascii=False) + "\n"
            _set_status("Copied JSON document to clipboard.")
        pyperclip.copy(text)

    def on_jsonedit() -> None:
        path = path_var.get().strip()
        if not path:
            return
        cmd = path_jsonedit
        if isinstance(cmd, Path):
            cmd = str(cmd)
        try:
            if isinstance(cmd, str):
                args = shlex.split(cmd) if " " in cmd else [cmd]
                if len(args) == 1:
                    resolved = shutil.which(args[0])
                    if resolved:
                        args[0] = resolved
            else:
                args = list(cmd)
            args.append(path)
            subprocess.Popen(args)
            _set_status("Launched JSONEdit.")
        except Exception:
            try:
                subprocess.Popen(f'"{cmd}" "{path}"', shell=True)
                _set_status("Launched JSONEdit.")
            except Exception as exc:
                _set_status(f"JSONEdit launch failed: {exc}")

    def _refresh_inventory_list() -> None:
        inv_path = Path(path_inventory)
        inv_result = core.load_json_file(inv_path)
        inv_obj = None
        if inv_result.error:
            inv_obj = {core.INVENTORY_KEY: {}}
        else:
            inv_top = core.ensure_top_level_object(inv_result.obj)
            inv_obj = inv_top.obj if inv_top.error is None else {core.INVENTORY_KEY: {}}

        inv_obj = core.ensure_inventory_obj(inv_obj)
        g["inventory_obj"] = inv_obj
        inventory_list.delete(0, tk.END)
        entries = inv_obj.get(core.INVENTORY_KEY, {})
        g["inventory_ids"] = []
        for doc_id in sorted(entries.keys()):
            inventory_list.insert(tk.END, f"{doc_id}")
            g["inventory_ids"].append(doc_id)

    def _on_inventory_select(_event=None) -> None:
        selection = inventory_list.curselection()
        if not selection:
            return
        idx = selection[0]
        if idx >= len(g["inventory_ids"]):
            return
        doc_id = g["inventory_ids"][idx]
        entry = g["inventory_obj"].get(core.INVENTORY_KEY, {}).get(doc_id)
        if not entry:
            return
        filepath = entry.get("filepath")
        if not filepath:
            _set_status("LOAD FAILED: inventory entry missing filepath.")
            return
        path_var.set(filepath)
        g["path_entry_value"] = filepath
        _update_copy_buttons_state()
        on_load()

    path_var.trace_add("write", lambda *_: _update_copy_buttons_state())

    _update_copy_buttons_state()
    _update_action_buttons_state()
    _refresh_inventory_list()
    inventory_list.bind("<<ListboxSelect>>", _on_inventory_select)
    _validate_header_loop()

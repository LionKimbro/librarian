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
from tkinter import ttk
from tkinter import filedialog

from . import core

try:
    import lionscliapp as app
except Exception:  # pragma: no cover - optional for direct execution
    app = None


VALIDATION_INTERVAL_MS = 750

COLOR_GOOD = "#1a7f37"
COLOR_BAD = "#d1242f"
COLOR_NEUTRAL = "#0969da"

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
        "indicator_json": "NOT_LOADED",
        "indicator_header": "NOT_LOADED",
        "status_message": "NOT LOADED. Select a file or paste a path, then click Load.",
    }


def create_app(window: tk.Misc, root: tk.Misc | None = None) -> dict[str, Any]:
    g = _create_state()
    g["root"] = root or window
    g["window"] = window
    g["path_inventory"] = _ctx_value("path.inventory", "inventory.json")
    g["path_jsonedit"] = _ctx_value("invoke.jsonedit", "jsonedit")
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

    body_pane = ttk.PanedWindow(window, orient="horizontal")
    body_pane.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=8, pady=6)

    left_frame = tk.Frame(body_pane)
    right_frame = tk.Frame(body_pane, width=200)

    body_pane.add(left_frame, weight=3)
    body_pane.add(right_frame, weight=1)

    # Path row
    tk.Label(top_frame, text="Path:").pack(side=tk.LEFT)
    path_entry = tk.Entry(top_frame, textvariable=path_var, width=80)
    path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=6)

    # Indicators row
    tk.Label(indicators_frame, text="JSON:").pack(side=tk.LEFT)
    json_indicator = tk.Label(indicators_frame, text="NOT_LOADED", width=10, anchor="w")
    json_indicator.pack(side=tk.LEFT, padx=(0, 10))

    tk.Label(indicators_frame, text="Header:").pack(side=tk.LEFT)
    header_indicator = tk.Label(indicators_frame, text="NOT_LOADED", width=10, anchor="w")
    header_indicator.pack(side=tk.LEFT, padx=(0, 10))

    # Status
    status_var = tk.StringVar(value=g["status_message"])
    status_label = tk.Label(
        status_frame, textvariable=status_var, anchor="w", justify=tk.LEFT, fg=COLOR_NEUTRAL
    )
    status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
    loaded_var = tk.StringVar(value="Loaded: (none)")
    loaded_label = tk.Label(status_frame, textvariable=loaded_var, anchor="e")
    loaded_label.pack(side=tk.RIGHT)

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

    inventory_buttons = tk.Frame(right_frame)
    inventory_buttons.pack(side=tk.TOP, fill=tk.X, pady=6)

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

    inv_reload_button = tk.Button(
        inventory_buttons, text="Reload", command=lambda: on_inventory_reload()
    )
    inv_reload_button.pack(side=tk.LEFT, padx=(0, 6))
    inv_copy_path_button = tk.Button(
        inventory_buttons, text="Copy Path", command=lambda: on_inventory_copy_path()
    )
    inv_copy_path_button.pack(side=tk.LEFT, padx=(0, 6))
    inv_copy_json_button = tk.Button(
        inventory_buttons, text="Copy JSON", command=lambda: on_inventory_copy_json(False)
    )
    inv_copy_json_button.pack(side=tk.LEFT, padx=(0, 6))
    inv_copy_json_min_button = tk.Button(
        inventory_buttons, text="(min)", command=lambda: on_inventory_copy_json(True)
    )
    inv_copy_json_min_button.pack(side=tk.LEFT, padx=(0, 6))
    inv_treeedit_button = tk.Button(
        inventory_buttons, text="TreeEdit", command=lambda: on_inventory_treeedit()
    )
    inv_treeedit_button.pack(side=tk.LEFT)

    g["widgets"] = {
        "path_entry": path_entry,
        "select_button": None,
        "load_button": None,
        "json_indicator": json_indicator,
        "header_indicator": header_indicator,
        "status_var": status_var,
        "loaded_var": loaded_var,
        "header_text": header_text,
        "save_checkbox": save_checkbox,
        "save_button": save_button,
        "index_button": index_button,
        "inventory_list": inventory_list,
        "copy_path_button": copy_path_button,
        "copy_tree_button": copy_tree_button,
        "copy_tree_comp_button": copy_tree_comp_button,
        "jsonedit_button": jsonedit_button,
        "inv_reload_button": inv_reload_button,
        "inv_copy_path_button": inv_copy_path_button,
        "inv_copy_json_button": inv_copy_json_button,
        "inv_copy_json_min_button": inv_copy_json_min_button,
        "inv_treeedit_button": inv_treeedit_button,
    }

    g["vars"] = {
        "path_var": path_var,
        "save_compressed_var": save_compressed_var,
    }

    g["inventory_ids"] = []

    def _color_for_state(state: str) -> str:
        if state in ("VALID", "PRESENT"):
            return COLOR_GOOD
        if state in ("INVALID",):
            return COLOR_BAD
        return COLOR_NEUTRAL

    def _status_color(msg: str) -> str:
        upper = msg.upper()
        if "FAILED" in upper or "INVALID" in upper:
            return COLOR_BAD
        if upper.startswith("READY") or upper.startswith("SAVED") or upper.startswith("INDEXED"):
            return COLOR_GOOD
        return COLOR_NEUTRAL

    def _render_indicators() -> None:
        json_state = g["indicator_json"]
        header_state = g["indicator_header"]
        json_indicator.config(text=json_state, fg=_color_for_state(json_state))
        header_indicator.config(text=header_state, fg=_color_for_state(header_state))

    def _render_status() -> None:
        status_var.set(g["status_message"])
        status_label.config(fg=_status_color(g["status_message"]))

    def _render_loaded_label() -> None:
        if g.get("loaded_path"):
            loaded_var.set(f"Loaded: {Path(g['loaded_path']).name}")
        else:
            loaded_var.set("Loaded: (none)")

    def _render_enablement() -> None:
        header_valid = g["header_text_last_valid_obj"] is not None
        doc_id_ok = False
        if header_valid:
            doc_id_ok = core.is_valid_document_id(
                g["header_text_last_valid_obj"].get("document-id")
            )
        save_enabled = bool(g["loaded_doc_obj"]) and header_valid and doc_id_ok
        save_button.config(state=tk.NORMAL if save_enabled else tk.DISABLED)

        index_enabled = bool(g["loaded_doc_obj"]) and g["loaded_disk_header_valid"]
        index_button.config(state=tk.NORMAL if index_enabled else tk.DISABLED)

        doc_tools_enabled = bool(g.get("loaded_path"))
        state = tk.NORMAL if doc_tools_enabled else tk.DISABLED
        copy_path_button.config(state=state)
        copy_tree_button.config(state=state)
        copy_tree_comp_button.config(state=state)
        jsonedit_button.config(state=state)

    def _render_inventory_list() -> None:
        inv_obj = g.get("inventory_obj")
        if inv_obj is None:
            return
        inventory_list.delete(0, tk.END)
        entries = inv_obj.get(core.INVENTORY_KEY, {})
        g["inventory_ids"] = []
        for doc_id in entries.keys():
            inventory_list.insert(tk.END, f"{doc_id}")
            g["inventory_ids"].append(doc_id)

    def render() -> None:
        _render_indicators()
        _render_status()
        _render_loaded_label()
        _render_enablement()
        _render_inventory_list()

    def set_status(text: str) -> None:
        g["status_message"] = text
        _render_status()

    def set_indicators(json_state: str, header_state: str) -> None:
        g["indicator_json"] = json_state
        g["indicator_header"] = header_state
        _render_indicators()

    def _set_header_text(text: str) -> None:
        header_text.delete("1.0", tk.END)
        header_text.insert("1.0", text)

    def _on_save_compressed_change() -> None:
        g["save_compressed"] = bool(save_compressed_var.get())

    def on_select() -> None:
        filename = filedialog.askopenfilename(
            title="Select JSON document",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if filename:
            path_var.set(filename)
            g["path_entry_value"] = filename
            on_load()

    select_button = tk.Button(top_frame, text="Select", command=on_select)
    select_button.pack(side=tk.LEFT, padx=2)
    g["widgets"]["select_button"] = select_button

    def on_load() -> None:
        path = path_var.get().strip()
        g["path_entry_value"] = path
        if not path:
            set_status("NOT LOADED. Select a file or paste a path, then click Load.")
            set_indicators("NOT_LOADED", "NOT_LOADED")
            g["loaded_doc_obj"] = None
            g["loaded_path"] = None
            g["loaded_doc_json_error"] = None
            render()
            return
        result = core.load_json_file(path)
        if result.error:
            g["loaded_doc_obj"] = None
            g["loaded_path"] = None
            g["loaded_doc_json_error"] = result.error
            set_indicators("INVALID", "NOT_LOADED")
            set_status(f"LOAD FAILED: {result.error}.")
            render()
            return
        top_level = core.ensure_top_level_object(result.obj)
        if top_level.error:
            g["loaded_doc_obj"] = None
            g["loaded_path"] = None
            g["loaded_doc_json_error"] = top_level.error
            set_indicators("INVALID", "NOT_LOADED")
            set_status(f"LOAD FAILED: {top_level.error}.")
            render()
            return

        g["loaded_doc_obj"] = top_level.obj
        g["loaded_path"] = path
        g["loaded_doc_json_error"] = None

        header = core.extract_header(top_level.obj)
        if header is None:
            header = core.normalize_header(None)
            set_indicators("VALID", "MISSING")
            set_status("HEADER MISSING: stub header created (not saved).")
            g["loaded_disk_header_valid"] = False
        else:
            header = core.normalize_header(header)
            set_indicators("VALID", "PRESENT")
            header_valid = core.validate_header_required(header)
            g["loaded_disk_header_valid"] = header_valid.error is None
            if header_valid.error:
                set_status("HEADER INVALID: document-id missing or empty.")
            else:
                set_status("READY: header valid. You may Save or Index.")

        g["loaded_header_obj"] = header
        _set_header_text(json.dumps(header, indent=2, ensure_ascii=False))
        _refresh_inventory_list()
        render()

    load_button = tk.Button(top_frame, text="Load", command=on_load)
    load_button.pack(side=tk.LEFT, padx=2)
    g["widgets"]["load_button"] = load_button

    def _validate_header_editor() -> None:
        text = header_text.get("1.0", tk.END).strip()
        if not text:
            g["header_text_last_valid_obj"] = None
            g["header_text_last_error"] = "empty"
            _render_enablement()
            return
        parsed = core.parse_json_text(text)
        if parsed.error:
            g["header_text_last_valid_obj"] = None
            g["header_text_last_error"] = parsed.error
            set_status(f"HEADER INVALID: {parsed.error}.")
            _render_enablement()
            return
        if not isinstance(parsed.obj, dict):
            g["header_text_last_valid_obj"] = None
            g["header_text_last_error"] = "header must be a JSON object"
            set_status("HEADER INVALID: header must be a JSON object.")
            _render_enablement()
            return

        g["header_text_last_valid_obj"] = parsed.obj
        g["header_text_last_error"] = None

        required = core.validate_header_required(parsed.obj)
        if required.error:
            set_status("HEADER INVALID: document-id missing or empty.")
        else:
            missing_recommended = [
                key for key in core.RECOMMENDED_HEADER_KEYS if key not in parsed.obj
            ]
            if missing_recommended:
                set_status("READY: header valid. Recommended keys missing.")
            else:
                set_status("READY: header valid. You may Save or Index.")

        _render_enablement()

    def _validate_header_loop() -> None:
        if not header_text.winfo_exists():
            return
        _validate_header_editor()
        g["validation_after_id"] = g["root"].after(VALIDATION_INTERVAL_MS, _validate_header_loop)

    def on_save() -> None:
        if not g["loaded_doc_obj"] or not g["loaded_path"]:
            set_status("NOT LOADED. Select a file or paste a path, then click Load.")
            return
        header_obj = g["header_text_last_valid_obj"]
        if header_obj is None:
            set_status("HEADER INVALID: cannot save.")
            return
        required = core.validate_header_required(header_obj)
        if required.error:
            set_status("HEADER INVALID: document-id missing or empty.")
            return

        updated_doc = core.update_document_header(g["loaded_doc_obj"], header_obj)
        formatted = core.format_json(updated_doc, compressed=bool(save_compressed_var.get()))
        core.atomic_write_text(g["loaded_path"], formatted)
        g["loaded_doc_obj"] = updated_doc
        g["loaded_disk_header_valid"] = True
        if save_compressed_var.get():
            set_status("SAVED: wrote document header to file (compressed).")
        else:
            set_status("SAVED: wrote document header to file (pretty).")
        _render_enablement()

    def on_index() -> None:
        if not g["loaded_path"]:
            set_status("NOT LOADED. Select a file or paste a path, then click Load.")
            return
        doc_result = core.load_json_file(g["loaded_path"])
        if doc_result.error:
            set_status(f"LOAD FAILED: {doc_result.error}.")
            return
        top_level = core.ensure_top_level_object(doc_result.obj)
        if top_level.error:
            set_status(f"LOAD FAILED: {top_level.error}.")
            return
        header = core.extract_header(top_level.obj)
        if header is None:
            set_status("HEADER INVALID: document-id missing or empty.")
            return
        header = core.normalize_header(header)
        required = core.validate_header_required(header)
        if required.error:
            set_status("HEADER INVALID: document-id missing or empty.")
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
            header["document-id"],
            str(g["loaded_path"]),
            header.get("title"),
            header.get("purpose"),
        )
        inv_text = core.format_json(inv_obj, compressed=False)
        core.atomic_write_text(inv_path, inv_text)
        g["inventory_obj"] = inv_obj
        _render_inventory_list()
        set_status(f"INDEXED: updated inventory.json entry for {header['document-id']}")

    def on_copy_path() -> None:
        path = g.get("loaded_path")
        if not path:
            return
        pyperclip.copy(str(path))
        set_status("Copied path to clipboard.")

    def on_copy_tree(compressed: bool) -> None:
        path = g.get("loaded_path")
        if not path:
            return
        doc_result = core.load_json_file(path)
        if doc_result.error:
            set_status(f"LOAD FAILED: {doc_result.error}.")
            return
        if compressed:
            text = json.dumps(doc_result.obj, separators=(",", ":"), ensure_ascii=False) + "\n"
            set_status("Copied JSON document to clipboard (compressed).")
        else:
            text = json.dumps(doc_result.obj, indent=2, ensure_ascii=False) + "\n"
            set_status("Copied JSON document to clipboard.")
        pyperclip.copy(text)

    def _launch_jsonedit(target_path: str, status_ok: str) -> None:
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
            args.append(target_path)
            subprocess.Popen(args)
            set_status(status_ok)
        except Exception:
            try:
                subprocess.Popen(f'"{cmd}" "{target_path}"', shell=True)
                set_status(status_ok)
            except Exception as exc:
                set_status(f"JSONEdit launch failed: {exc}")

    def on_jsonedit() -> None:
        path = g.get("loaded_path")
        if not path:
            return
        _launch_jsonedit(str(path), "Launched JSONEdit.")

    def on_inventory_copy_path() -> None:
        pyperclip.copy(str(path_inventory))
        set_status("Copied inventory path to clipboard.")

    def on_inventory_reload() -> None:
        _refresh_inventory_list()
        set_status("Reloaded inventory.")

    def on_inventory_copy_json(compressed: bool) -> None:
        inv_result = core.load_json_file(path_inventory)
        if inv_result.error:
            set_status(f"LOAD FAILED: {inv_result.error}.")
            return
        if compressed:
            text = json.dumps(inv_result.obj, separators=(",", ":"), ensure_ascii=False) + "\n"
            set_status("Copied inventory JSON to clipboard (compressed).")
        else:
            text = json.dumps(inv_result.obj, indent=2, ensure_ascii=False) + "\n"
            set_status("Copied inventory JSON to clipboard.")
        pyperclip.copy(text)

    def on_inventory_treeedit() -> None:
        _launch_jsonedit(str(path_inventory), "Launched JSONEdit for inventory.")

    def _refresh_inventory_list() -> None:
        inv_path = Path(path_inventory)
        inv_result = core.load_json_file(inv_path)
        if inv_result.error:
            g["inventory_obj"] = {core.INVENTORY_KEY: {}}
        else:
            inv_top = core.ensure_top_level_object(inv_result.obj)
            g["inventory_obj"] = (
                inv_top.obj if inv_top.error is None else {core.INVENTORY_KEY: {}}
            )
        _render_inventory_list()

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
            set_status("LOAD FAILED: inventory entry missing filepath.")
            return
        path_var.set(filepath)
        g["path_entry_value"] = filepath
        on_load()

    def _bind_shortcuts() -> None:
        g["root"].bind_all("<Control-s>", lambda _e: on_save())
        g["root"].bind_all("<Control-S>", lambda _e: on_save())

    path_var.trace_add("write", lambda *_: None)

    _refresh_inventory_list()
    _render_indicators()
    _render_status()
    _render_loaded_label()
    _render_enablement()

    inventory_list.bind("<<ListboxSelect>>", _on_inventory_select)
    _bind_shortcuts()
    _validate_header_loop()

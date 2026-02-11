"""GUI integration tests using tkintertester (spec-driven)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import librarian.gui as gui

try:
    import tkintertester.harness as harness
except Exception:  # pragma: no cover - tkintertester may not be installed in CI
    harness = None


tests = []


def add_test(title, steps):
    if harness is not None and hasattr(harness, "add_test"):
        return harness.add_test(title, steps)
    test = {
        "title": title,
        "steps": list(steps),
        "status": None,
        "fail_message": None,
        "exception": None,
    }
    tests.append(test)
    return test


APP = {
    "entry": gui.app_entry,
    "exit": gui.app_exit,
}


T = {}


def _require_state():
    state = gui.get_app_state()
    if state is None:
        return None
    return state


def _set_path(path: str) -> None:
    state = _require_state()
    widgets = state["widgets"]
    entry = widgets["path_entry"]
    entry.delete(0, "end")
    entry.insert(0, path)


def _load_click() -> None:
    state = _require_state()
    widgets = state["widgets"]
    widgets["load_button"].invoke()


def _status_text() -> str:
    state = _require_state()
    return state["widgets"]["status_var"].get()


def _indicator_text(name: str) -> str:
    state = _require_state()
    return state["widgets"][name].cget("text")

def _button_state(name: str) -> str:
    state = _require_state()
    return state["widgets"][name].cget("state")


def _set_header_text(text: str) -> None:
    state = _require_state()
    header = state["widgets"]["header_text"]
    header.delete("1.0", "end")
    header.insert("1.0", text)


def _make_doc(path: Path, header: dict, extra: dict | None = None) -> None:
    doc = {"document": header}
    if extra:
        doc.update(extra)
    path.write_text(json.dumps(doc, indent=2), encoding="utf-8")


def step_setup_valid_doc():
    tmp = tempfile.TemporaryDirectory()
    T["tmp"] = tmp
    doc_path = Path(tmp.name) / "doc.json"
    _make_doc(doc_path, {"document_id": "tk.test.valid", "title": "Title"}, {"x": 1})
    T["doc_path"] = str(doc_path)
    return "next", None


def step_load_valid_doc():
    _set_path(T["doc_path"])
    _load_click()
    return "next", 100


def step_wait_validation():
    return "next", 800


def step_assert_valid_loaded():
    if _indicator_text("json_indicator") != "VALID":
        return "fail", "json indicator not VALID"
    if _indicator_text("header_indicator") != "PRESENT":
        return "fail", "header indicator not PRESENT"
    status = _status_text()
    if not status.startswith("READY"):
        return "fail", f"unexpected status: {status}"
    T["tmp"].cleanup()
    return "success", None


def step_setup_invalid_doc():
    tmp = tempfile.TemporaryDirectory()
    T["tmp"] = tmp
    doc_path = Path(tmp.name) / "bad.json"
    doc_path.write_text("{bad}", encoding="utf-8")
    T["doc_path"] = str(doc_path)
    return "next", None


def step_load_invalid_doc():
    _set_path(T["doc_path"])
    _load_click()
    return "next", 100


def step_assert_invalid_load():
    if _indicator_text("json_indicator") != "INVALID":
        return "fail", "json indicator not INVALID"
    status = _status_text()
    if "LOAD FAILED" not in status:
        return "fail", f"unexpected status: {status}"
    T["tmp"].cleanup()
    return "success", None


def step_setup_header_edit():
    tmp = tempfile.TemporaryDirectory()
    T["tmp"] = tmp
    doc_path = Path(tmp.name) / "doc.json"
    _make_doc(doc_path, {"document_id": "tk.test.edit"})
    T["doc_path"] = str(doc_path)
    return "next", None


def step_load_for_edit():
    _set_path(T["doc_path"])
    _load_click()
    return "next", 100


def step_edit_header_invalid():
    _set_header_text("{bad}")
    return "next", 800


def step_assert_header_invalid():
    status = _status_text()
    if "HEADER INVALID" not in status:
        return "fail", f"unexpected status: {status}"
    T["tmp"].cleanup()
    return "success", None


add_test(
    "Load valid JSON document with header",
    [step_setup_valid_doc, step_load_valid_doc, step_wait_validation, step_assert_valid_loaded],
)

add_test(
    "Load invalid JSON document",
    [step_setup_invalid_doc, step_load_invalid_doc, step_assert_invalid_load],
)

add_test(
    "Edit header text to invalid JSON",
    [step_setup_header_edit, step_load_for_edit, step_edit_header_invalid, step_assert_header_invalid],
)


def step_setup_button_doc():
    tmp = tempfile.TemporaryDirectory()
    T["tmp"] = tmp
    doc_path = Path(tmp.name) / "doc.json"
    _make_doc(doc_path, {"document_id": "tk.test.buttons"})
    T["doc_path"] = str(doc_path)
    return "next", None


def step_assert_buttons_initial_disabled():
    if _button_state("save_button") != "disabled":
        return "fail", "save_button should be disabled before load"
    if _button_state("index_button") != "disabled":
        return "fail", "index_button should be disabled before load"
    if _button_state("copy_path_button") != "disabled":
        return "fail", "copy_path_button should be disabled before load"
    if _button_state("copy_tree_button") != "disabled":
        return "fail", "copy_tree_button should be disabled before load"
    if _button_state("copy_tree_comp_button") != "disabled":
        return "fail", "copy_tree_comp_button should be disabled before load"
    if _button_state("jsonedit_button") != "disabled":
        return "fail", "jsonedit_button should be disabled before load"
    return "next", None


def step_load_for_buttons():
    _set_path(T["doc_path"])
    _load_click()
    return "next", 800


def step_assert_buttons_after_load():
    if _button_state("save_button") != "normal":
        return "fail", "save_button should be enabled after valid load"
    if _button_state("index_button") != "normal":
        return "fail", "index_button should be enabled after valid load"
    if _button_state("copy_path_button") != "normal":
        return "fail", "copy_path_button should be enabled after load"
    if _button_state("copy_tree_button") != "normal":
        return "fail", "copy_tree_button should be enabled after load"
    if _button_state("copy_tree_comp_button") != "normal":
        return "fail", "copy_tree_comp_button should be enabled after load"
    if _button_state("jsonedit_button") != "normal":
        return "fail", "jsonedit_button should be enabled after load"
    T["tmp"].cleanup()
    return "success", None


add_test(
    "Buttons enable/disable based on load state",
    [
        step_setup_button_doc,
        step_assert_buttons_initial_disabled,
        step_load_for_buttons,
        step_assert_buttons_after_load,
    ],
)

"""CLI entrypoint for Librarian."""

import lionscliapp as app

from .gui import gui_main


def _declare_app():
    app.declare_app("librarian", "0.1")
    app.describe_app("Inspect, edit, save, and index JSON document headers into inventory.json.")
    app.declare_projectdir(".librarian")

    app.declare_key("path.inventory", "inventory.json")
    app.describe_key("path.inventory", "Path to the inventory.json file.")

    app.declare_key("invoke.jsonedit", "jsonedit")
    app.describe_key("invoke.jsonedit", "Command or path used to launch JSONEdit.")

    app.declare_key("path.inbox", ".librarian/inbox")
    app.describe_key("path.inbox", "Directory to poll for incoming Patchboard messages.")

    app.declare_key("path.outbox", ".librarian/outbox")
    app.describe_key("path.outbox", "Directory to write outgoing Patchboard messages.")

    app.declare_cmd("", gui_main)
    app.describe_cmd("", "Launch the Librarian GUI.")


def main() -> None:
    _declare_app()
    app.main()


if __name__ == "__main__":
    main()

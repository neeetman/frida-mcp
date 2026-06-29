from __future__ import annotations

import os

from .server import build_server
from .session import SessionManager
from .store import ProjectStore


def main() -> None:
    project = os.environ.get("FRIDA_MCP_PROJECT", "./session.fmcp")
    store = ProjectStore(project)
    manager = SessionManager(store)
    build_server(manager).run()


if __name__ == "__main__":
    main()

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from .session import SessionManager


def build_server(manager: SessionManager) -> FastMCP:
    mcp = FastMCP("frida-mcp")
    store = manager.store

    @mcp.tool()
    def list_processes() -> list[dict]:
        """List processes visible to the local Frida device."""
        return manager.list_processes()

    @mcp.tool()
    def spawn(program: str, gated: bool = True) -> dict:
        """Spawn a program suspended (gated) so hooks can be installed first."""
        return manager.spawn(program, gated=gated)

    @mcp.tool()
    def attach(target: str) -> dict:
        """Attach to a running process by name or numeric pid (as string)."""
        t: int | str = int(target) if target.isdigit() else target
        return manager.attach(t)

    @mcp.tool()
    def resume(session_id: int) -> dict:
        """Resume a gated/spawned process so it starts running."""
        return manager.resume(session_id)

    @mcp.tool()
    def detach(session_id: int) -> dict:
        """Detach Frida from a session (process keeps running)."""
        manager.detach(session_id)
        return {"detached": session_id}

    @mcp.tool()
    def kill(session_id: int) -> dict:
        """Kill the target process of a session."""
        return manager.kill(session_id)

    @mcp.tool()
    def list_modules(session_id: int) -> list[dict]:
        """List loaded modules in the target."""
        return manager.list_modules(session_id)

    @mcp.tool()
    def eval_js(session_id: int, code: str) -> dict:
        """Evaluate JS in the resident agent's persistent context."""
        return manager.evaluate(session_id, code)

    @mcp.tool()
    def add_hook(session_id: int, target: str) -> dict:
        """Hook a function (module!export or hex address); calls stream to disk."""
        return manager.add_hook(session_id, target)

    @mcp.tool()
    def trace_api(session_id: int, pattern: str) -> dict:
        """frida-trace style: hook all exports matching module!glob (e.g. kernel32!CreateFile*)."""
        return manager.trace_api(session_id, pattern)

    @mcp.tool()
    def read_memory(session_id: int, address: str, size: int) -> dict:
        """Read `size` bytes at `address` (hex string) from the live process."""
        return manager.read_memory(session_id, address, size)

    @mcp.tool()
    def write_memory(session_id: int, address: str, hex_bytes: str) -> dict:
        """Write hex-encoded bytes at `address`."""
        return manager.write_memory(session_id, address, hex_bytes)

    @mcp.tool()
    def scan_memory(session_id: int, pattern: str, protection: str = "r--") -> list[dict]:
        """AOB/pattern scan over ranges with the given protection."""
        return manager.scan_memory(session_id, pattern, protection)

    @mcp.tool()
    def disassemble(session_id: int, address: str, count: int = 10) -> list[dict]:
        """Disassemble `count` instructions at `address` from live memory."""
        return manager.disassemble(session_id, address, count)

    @mcp.tool()
    def list_sessions() -> list[dict]:
        """List all sessions (alive and dead) recorded in the project."""
        return store.list_sessions()

    @mcp.tool()
    def resume_session(session_id: int) -> dict:
        """Re-attach a prior session and reinstall its hooks if the target is alive."""
        return manager.resume_session(session_id)

    @mcp.tool()
    def read_events(session_id: int, offset: int = 0, limit: int = 100,
                    type_filter: str | None = None) -> list[dict]:
        """Read captured events (hooks/repl/errors) from the trace log."""
        return store.read_events(session_id, offset, limit, type_filter)

    @mcp.tool()
    def add_note(session_id: int, text: str) -> dict:
        """Attach a freeform note to a session."""
        return {"note_id": store.add_note(session_id, text)}

    @mcp.tool()
    def list_notes(session_id: int) -> list[dict]:
        """List notes for a session."""
        return store.list_notes(session_id)

    return mcp

from frida_mcp.server import build_server


class FakeManager:
    def __init__(self):
        self.calls = []
        self.store = self  # double as store for note tools
        self._sessions = [{"id": 1, "target": "game.exe", "state": "alive"}]

    def list_sessions(self):
        self.calls.append(("list_sessions",))
        return self._sessions

    def evaluate(self, session_id, code):
        self.calls.append(("evaluate", session_id, code))
        return {"type": "number", "value": 2, "preview": "2"}

    def add_note(self, session_id, text):
        self.calls.append(("add_note", session_id, text))
        return 7


def _tool(server, name):
    # FastMCP stores registered tools; fetch the underlying callable.
    return server._tool_manager._tools[name].fn


def test_eval_tool_forwards():
    mgr = FakeManager()
    server = build_server(mgr)
    fn = _tool(server, "eval_js")
    result = fn(session_id=1, code="1+1")
    assert result["preview"] == "2"
    assert ("evaluate", 1, "1+1") in mgr.calls


def test_list_sessions_tool():
    mgr = FakeManager()
    server = build_server(mgr)
    fn = _tool(server, "list_sessions")
    assert fn()[0]["target"] == "game.exe"

from frida_mcp.session import is_same_process, process_fingerprint, SessionManager
from frida_mcp.store import ProjectStore


class FakeProc:
    def __init__(self, pid, name):
        self.pid = pid
        self.name = name


class FakeDevice:
    def __init__(self, procs):
        self._procs = procs

    def enumerate_processes(self):
        return self._procs


def test_fingerprint_found_and_missing():
    dev = FakeDevice([FakeProc(100, "game.exe"), FakeProc(200, "x.exe")])
    assert process_fingerprint(dev, 100) == "game.exe"
    assert process_fingerprint(dev, 999) is None


def test_is_same_process_matches_name():
    dev = FakeDevice([FakeProc(100, "game.exe")])
    assert is_same_process(dev, 100, "game.exe") is True


def test_is_same_process_detects_pid_reuse():
    # pid 100 is alive but is now a *different* program → not the same session
    dev = FakeDevice([FakeProc(100, "other.exe")])
    assert is_same_process(dev, 100, "game.exe") is False


def test_is_same_process_dead():
    dev = FakeDevice([])
    assert is_same_process(dev, 100, "game.exe") is False


def test_resume_marks_dead_when_pid_gone(tmp_path):
    store = ProjectStore(tmp_path / "p.fmcp")
    sid = store.create_session("game.exe", "spawn", "game.exe", [], "game.exe", pid=100)
    dev = FakeDevice([])  # no live processes → pid 100 is gone
    mgr = SessionManager(store, device=dev)
    result = mgr.resume_session(sid)
    assert result["status"] == "dead"
    assert result["reinstalled"] == 0
    assert store.get_session(sid)["state"] == "dead"


class _FakeExports:
    def __init__(self):
        self.calls = []

    def add_hook(self, target):
        self.calls.append(("add_hook", target))
        return {"id": 1}

    def trace_api(self, pattern):
        self.calls.append(("trace_api", pattern))
        return {"ids": [1], "matched": 1}


class _FakeScript:
    def __init__(self, exports):
        self.exports_sync = exports

    def on(self, *a, **k):
        pass

    def load(self):
        pass


class _FakeFridaSession:
    def __init__(self, exports):
        self._exports = exports

    def create_script(self, source):
        return _FakeScript(self._exports)

    def detach(self):
        pass


class _FakeDeviceAttach(FakeDevice):
    def __init__(self, procs, exports):
        super().__init__(procs)
        self._exports = exports

    def attach(self, pid):
        return _FakeFridaSession(self._exports)


def test_add_hook_propagates_error_without_persisting(tmp_path):
    from frida_mcp.store import ProjectStore
    from frida_mcp.session import SessionManager, Session
    store = ProjectStore(tmp_path / "p.fmcp")
    sid = store.create_session("t", "attach", None, None, "t", pid=1)
    exports = _FakeExports()
    # override add_hook to simulate a failed hook
    exports.add_hook = lambda target: {"error": "boom"}
    mgr = SessionManager(store, device=FakeDevice([]))
    mgr.live[sid] = Session(sid, 1, object(), object(), exports)
    result = mgr.add_hook(sid, "bad!sym")
    assert "error" in result
    assert store.list_instruments(sid) == []  # no phantom instrument persisted


def test_resume_reinstalls_hook_and_trace(tmp_path):
    from frida_mcp.store import ProjectStore
    from frida_mcp.session import SessionManager
    store = ProjectStore(tmp_path / "p.fmcp")
    sid = store.create_session("game.exe", "spawn", "game.exe", [], "game.exe", pid=100)
    store.add_instrument(sid, "hook", "kernel32!CreateFileW", "kernel32!CreateFileW")
    store.add_instrument(sid, "trace", "kernel32!Reg*", "kernel32!Reg*")
    exports = _FakeExports()
    dev = _FakeDeviceAttach([FakeProc(100, "game.exe")], exports)
    mgr = SessionManager(store, device=dev)
    result = mgr.resume_session(sid)
    assert result["status"] == "reattached"
    assert result["reinstalled"] == 2
    assert ("add_hook", "kernel32!CreateFileW") in exports.calls
    assert ("trace_api", "kernel32!Reg*") in exports.calls


def test_resolve_program_resolves_bare_name_on_path():
    import os
    from frida_mcp.session import SessionManager
    bare = "cmd.exe" if os.name == "nt" else "sh"
    resolved = SessionManager._resolve_program(bare)
    assert os.path.isabs(resolved)
    assert os.path.isfile(resolved)
    assert os.path.basename(resolved).lower() == bare.lower()


def test_resolve_program_passes_through_paths_and_unknown_names():
    import os
    from frida_mcp.session import SessionManager
    explicit = "C:\\foo\\bar.exe" if os.name == "nt" else "/foo/bar.exe"
    assert SessionManager._resolve_program(explicit) == explicit
    relative = ".\\foo.exe" if os.name == "nt" else "./foo.exe"
    assert SessionManager._resolve_program(relative) == relative
    assert SessionManager._resolve_program("no_such_binary_xyz") == "no_such_binary_xyz"

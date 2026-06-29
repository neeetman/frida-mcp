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

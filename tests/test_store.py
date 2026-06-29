import pytest
from frida_mcp.store import ProjectStore


def test_create_and_get_session(tmp_path):
    store = ProjectStore(tmp_path / "proj.fmcp")
    sid = store.create_session(
        target="game.exe", mode="spawn",
        exe_path=r"C:\g\game.exe", args=["--debug"], fingerprint="game.exe",
    )
    s = store.get_session(sid)
    assert s["id"] == sid
    assert s["target"] == "game.exe"
    assert s["mode"] == "spawn"
    assert s["exe_path"] == r"C:\g\game.exe"
    assert s["args"] == ["--debug"]
    assert s["fingerprint"] == "game.exe"
    assert s["state"] == "alive"


def test_list_and_state(tmp_path):
    store = ProjectStore(tmp_path / "proj.fmcp")
    a = store.create_session("a", "attach", None, None, "a")
    b = store.create_session("b", "attach", None, None, "b")
    store.set_session_state(a, "dead")
    listed = store.list_sessions()
    assert [s["id"] for s in listed] == [b, a]  # newest first
    assert store.get_session(a)["state"] == "dead"


def test_directory_layout(tmp_path):
    proj = tmp_path / "proj.fmcp"
    ProjectStore(proj)
    assert (proj / "db.sqlite").exists()
    assert (proj / "traces").is_dir()


def test_set_session_state_rejects_invalid(tmp_path):
    store = ProjectStore(tmp_path / "proj.fmcp")
    sid = store.create_session("t", "attach", None, None, "t")
    with pytest.raises(ValueError):
        store.set_session_state(sid, "crashed")


def test_append_and_read_events(tmp_path):
    store = ProjectStore(tmp_path / "proj.fmcp")
    sid = store.create_session("t", "attach", None, None, "t")
    n0 = store.append_event(sid, {"type": "hook", "name": "open", "arg": "a"})
    n1 = store.append_event(sid, {"type": "repl", "code": "1+1"})
    n2 = store.append_event(sid, {"type": "hook", "name": "read"})
    assert [n0, n1, n2] == [0, 1, 2]

    all_events = store.read_events(sid)
    assert [e["line"] for e in all_events] == [0, 1, 2]
    assert all_events[0]["event"]["name"] == "open"

    hooks = store.read_events(sid, type_filter="hook")
    assert [e["event"]["name"] for e in hooks] == ["open", "read"]
    assert store.count_events(sid) == 3
    assert store.count_events(sid, type_filter="hook") == 2


def test_read_events_pagination(tmp_path):
    store = ProjectStore(tmp_path / "proj.fmcp")
    sid = store.create_session("t", "attach", None, None, "t")
    for i in range(10):
        store.append_event(sid, {"type": "hook", "i": i})
    page = store.read_events(sid, offset=3, limit=4)
    assert [e["event"]["i"] for e in page] == [3, 4, 5, 6]


def test_events_survive_reopen(tmp_path):
    proj = tmp_path / "proj.fmcp"
    store = ProjectStore(proj)
    sid = store.create_session("t", "attach", None, None, "t")
    store.append_event(sid, {"type": "hook", "x": 1})
    store.close()
    reopened = ProjectStore(proj)
    assert reopened.read_events(sid)[0]["event"]["x"] == 1


def test_read_events_type_filter_with_pagination(tmp_path):
    store = ProjectStore(tmp_path / "proj.fmcp")
    sid = store.create_session("t", "attach", None, None, "t")
    for i in range(6):
        store.append_event(sid, {"type": "hook" if i % 2 == 0 else "repl", "i": i})
    # hooks are at i=0,2,4 → skip the first, take one
    page = store.read_events(sid, offset=1, limit=1, type_filter="hook")
    assert [e["event"]["i"] for e in page] == [2]

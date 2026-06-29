import json
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

import sys
import time
import pytest

from frida_mcp.store import ProjectStore
from frida_mcp.session import SessionManager

pytestmark = pytest.mark.live

SLEEPER = [sys.executable, "-c", "import time; time.sleep(300)"]


@pytest.fixture
def session(tmp_path):
    """Spawn a dedicated child process, attach, resume, and tear it down."""
    store = ProjectStore(tmp_path / "live.fmcp")
    mgr = SessionManager(store)
    info = mgr.spawn(SLEEPER, gated=True)
    sid = info["id"]
    mgr.resume(sid)
    time.sleep(0.3)  # let the interpreter reach its sleep
    try:
        yield mgr, sid
    finally:
        try:
            mgr.kill(sid)
        except Exception:
            pass


def test_eval_returns_structured_values(session):
    mgr, sid = session
    num = mgr.evaluate(sid, "Process.id")
    assert num["type"] == "number"
    base = mgr.evaluate(sid, "Process.enumerateModules()[0].base")
    assert base["type"] == "pointer"
    assert base["value"].startswith("0x")


def test_disassemble_live(session):
    mgr, sid = session
    base = mgr.evaluate(sid, "Process.enumerateModules()[0].base")["value"]
    insns = mgr.disassemble(sid, base, 3)
    assert len(insns) == 3
    assert "mnemonic" in insns[0]


def test_hook_captures_event_to_jsonl(session):
    mgr, sid = session
    target = ("kernel32!GetLastError" if sys.platform == "win32"
              else "libc.so.6!getpid")
    mgr.add_hook(sid, target)
    # Trigger the hooked function from inside the target process itself.
    mod, name = target.split("!")
    mgr.evaluate(
        sid,
        f"var f = new NativeFunction(Module.getExportByName('{mod}', '{name}'),"
        f"'uint32', []); for (var i = 0; i < 3; i++) f();",
    )
    time.sleep(0.5)  # allow send() events to flush to the store
    events = mgr.store.read_events(sid, type_filter="hook")
    assert len(events) >= 1
    assert events[0]["event"]["target"] == target

from __future__ import annotations

import importlib.resources as resources
import os.path
from dataclasses import dataclass

from .store import ProjectStore
from .values import preview_of


def _agent_source() -> str:
    return resources.files("frida_mcp").joinpath("agent.js").read_text(
        encoding="utf-8"
    )


def process_fingerprint(device, pid: int) -> str | None:
    for proc in device.enumerate_processes():
        if proc.pid == pid:
            return proc.name
    return None


def is_same_process(device, pid: int, fingerprint: str) -> bool:
    return process_fingerprint(device, pid) == fingerprint


@dataclass
class Session:
    session_id: int
    pid: int
    frida_session: object
    script: object
    exports: object


class SessionManager:
    def __init__(self, store: ProjectStore, device=None) -> None:
        self.store = store
        self._device = device
        self.live: dict[int, Session] = {}

    @property
    def device(self):
        if self._device is None:
            import frida
            self._device = frida.get_local_device()
        return self._device

    def _load_script(self, pid: int):
        frida_session = self.device.attach(pid)
        script = frida_session.create_script(_agent_source())
        script.on("message", lambda msg, data: self._on_message(pid, msg, data))
        script.load()
        return frida_session, script

    def _on_message(self, pid: int, message: dict, data) -> None:
        session_id = self._pid_to_session_id(pid)
        if session_id is None:
            return
        if message.get("type") == "send":
            self.store.append_event(session_id, message["payload"])
        elif message.get("type") == "error":
            self.store.append_event(
                session_id, {"type": "error", "description": message.get("description")}
            )

    def _pid_to_session_id(self, pid: int) -> int | None:
        for sid, sess in self.live.items():
            if sess.pid == pid:
                return sid
        return None

    def spawn(self, program, gated: bool = True) -> dict:
        argv = program if isinstance(program, list) else [program]
        pid = self.device.spawn(argv)
        fingerprint = process_fingerprint(self.device, pid) or os.path.basename(argv[0])
        sid = self.store.create_session(
            target=argv[0], mode="spawn", exe_path=argv[0],
            args=argv[1:], fingerprint=fingerprint, pid=pid,
        )
        frida_session, script = self._load_script(pid)
        self.live[sid] = Session(sid, pid, frida_session, script, script.exports_sync)
        if not gated:
            self.device.resume(pid)
        return self.store.get_session(sid)

    def attach(self, target) -> dict:
        proc = self._resolve(target)
        sid = self.store.create_session(
            target=proc.name, mode="attach", exe_path=None,
            args=None, fingerprint=proc.name, pid=proc.pid,
        )
        frida_session, script = self._load_script(proc.pid)
        self.live[sid] = Session(sid, proc.pid, frida_session, script, script.exports_sync)
        return self.store.get_session(sid)

    def _resolve(self, target):
        if isinstance(target, int):
            for proc in self.device.enumerate_processes():
                if proc.pid == target:
                    return proc
            raise ValueError(f"no process with pid {target}")
        for proc in self.device.enumerate_processes():
            if proc.name == target:
                return proc
        raise ValueError(f"no process named {target!r}")

    def resume_session(self, session_id: int) -> dict:
        row = self.store.get_session(session_id)
        if row is None:
            raise ValueError(f"no session {session_id}")
        if session_id in self.live:
            return {"session": row, "status": "already_live", "reinstalled": 0}
        if not is_same_process(self.device, row["pid"], row["fingerprint"]):
            self.store.set_session_state(session_id, "dead")
            return {"session": self.store.get_session(session_id),
                    "status": "dead", "reinstalled": 0}
        frida_session, script = self._load_script(row["pid"])
        sess = Session(session_id, row["pid"], frida_session, script, script.exports_sync)
        self.live[session_id] = sess
        reinstalled = 0
        for inst in self.store.list_instruments(session_id):
            if inst["kind"] == "hook":
                sess.exports.add_hook(inst["target_expr"])
                reinstalled += 1
        self.store.set_session_state(session_id, "alive")
        return {"session": self.store.get_session(session_id),
                "status": "reattached", "reinstalled": reinstalled}

    def evaluate(self, session_id: int, code: str) -> dict:
        sess = self._require_live(session_id)
        value = sess.exports.evaluate(code)
        self.store.add_repl(session_id, code, preview_of(value))
        return value

    def add_hook(self, session_id: int, target_expr: str) -> dict:
        sess = self._require_live(session_id)
        result = sess.exports.add_hook(target_expr)
        iid = self.store.add_instrument(session_id, "hook", target_expr, target_expr)
        return {"instrument_id": iid, "agent_hook_id": result["id"]}

    def detach(self, session_id: int) -> None:
        sess = self.live.pop(session_id, None)
        if sess is not None:
            sess.frida_session.detach()

    def _require_live(self, session_id: int) -> Session:
        if session_id not in self.live:
            raise ValueError(f"session {session_id} is not live; resume it first")
        return self.live[session_id]

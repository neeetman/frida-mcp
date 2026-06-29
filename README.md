# frida-mcp

A simple MCP server exposing persistent, scriptable [Frida](https://frida.re)
dynamic instrumentation to an AI agent. Built for Windows reversing,
malware/security analysis, and general dynamic debugging.

## Install

    pip install -e .

Requires Python 3.11+. Frida is the only runtime dependency.

## Run

    FRIDA_MCP_PROJECT=./mytarget.fmcp python -m frida_mcp

Register it with your MCP client (stdio transport). All state lands in the
`.fmcp` project directory: `db.sqlite` (metadata) + `traces/*.jsonl` (events).

## Capabilities

- Process control: spawn (gated), attach, resume, detach, kill, list modules.
- Memory: read, write, AOB/pattern scan, ranges.
- Hooks: `add_hook`, `trace_api` (e.g. `kernel32!CreateFile*`), replace,
  backtraces — all calls stream to disk.
- `eval_js`: run JS in a persistent in-process context; results come back as
  structured typed values you can feed straight into `read_memory`/`disassemble`.
- `disassemble`: read N instructions from live memory (Capstone).
- Persistence: `list_sessions` / `resume_session` re-attach and reinstall hooks
  if the target is alive, or tell you to re-spawn if it died. Events, REPL
  history, and notes survive restarts.

Deep static analysis (xrefs, function boundaries, decompilation) is out of
scope — use an IDA or x64dbg MCP for that.

## Tests

    pytest                       # unit tests (no target needed)
    pytest -m live               # integration tests (attach to a real process)

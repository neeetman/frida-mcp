# frida-mcp 设计文档

- 日期:2026-06-29
- 状态:已通过 brainstorming 评审,待写实现计划
- 平台:Windows 为主(Frida Python binding 跨平台,设计不锁死)

## 1. 背景与目标

搭建一个**简单**的 Frida MCP 服务器,把动态插桩能力暴露给 AI agent
(Claude)。灵感来自 Luma 的两个核心特性,但**重新理解到 MCP 语境**——
使用者是 agent,不是坐在 REPL 前的人:

- **Scriptable**:agent 调用工具在目标进程里 eval JS,拿到**结构化
  JSON 返回值**(而非渲染成可点击 UI 的字符串)。
- **Persistent**:会话 / 脚本 / 事件流落盘,**agent 在新对话里能恢复
  工作现场**(而非弹横幅让人点 Re-Spawn)。

### 使用场景(三者公约数)

1. 游戏 / 应用逆向(扫内存、hook 函数、改返回值、dump 结构体)
2. 恶意软件 / 安全分析(监控 Win32 API、解密、行为追踪)
3. 通用动态调试(给任意进程做探针、辅助理解程序逻辑)

### 非目标(明确砍掉 / 交给别的 MCP)

- 深度静态分析:xref、函数边界、伪代码反编译 → 交给 IDA / x64dbg MCP。
- 不引入 radare2(破坏 pip 零依赖、r2 看不到活进程、子进程生命周期在
  Windows 更脆弱、其增量价值已被 IDA 覆盖)。反汇编只做"读 N 条指令"。
- 远程 frida-server(E):本地够用,需要时再加。
- 真正"续传"进程内 hook 运行时状态:物理上不可能(进程死即丢)。持久化
  的是**捕获到的数据**+ 进程活着就续抓 + 死了能一键重建注入现场。

## 2. 技术选型

- 语言/运行时:**Python**(`pip install frida` 即可,Frida Python API
  是一等公民;官方 MCP Python SDK)。
- 反汇编:**Frida 内置 Capstone**(`Instruction.parse`),零额外依赖,
  反汇编的是活进程当前真实字节。
- 持久化:**SQLite(元数据)+ 文件(大块 trace)** 混合,仿 Luma 的
  `db.sqlite` + `traces/`。

## 3. 整体架构

```
┌─────────────┐   MCP (stdio)   ┌──────────────────────┐
│   Claude    │ ──────────────► │  frida-mcp (Python)  │
│  (agent)    │ ◄────────────── │  - MCP 工具层         │
└─────────────┘                 │  - SessionManager     │
                                │  - Persistence (SQLite│
                                │    + traces/*.jsonl)   │
                                └──────────┬───────────┘
                                           │ frida (python binding)
                                           ▼
                                ┌──────────────────────┐
                                │  常驻 Agent Script    │
                                │  (注入目标进程的 JS)  │
                                │  - rpc.exports.eval   │
                                │  - hook/trace 注册表  │
                                │  - send() 抛事件      │
                                └──────────────────────┘
```

三层职责:

- **MCP 工具层**:用官方 Python MCP SDK 把 Frida 能力暴露成工具。
- **SessionManager**:管理 attach/spawn 的进程会话、常驻脚本句柄、事件流
  落盘、恢复流程。
- **常驻 Agent Script**:一段长期存活的 JS,注入后通过 `rpc.exports`
  提供 `eval`、hook 注册等;所有 hook 抓到的数据用 `send()` 抛回 Python
  端,Python 端流式写盘。

**关键设计**:每个目标进程只注入**一个常驻脚本**,所有 eval/hook 都在
它的同一上下文里,状态跨多次工具调用保留——这是 Scriptable 和 Persistent
的共同基础。

## 4. MCP 工具清单(v1)

### A. 会话 / 进程接管

- `list_processes` / `list_devices`
- `spawn(program, gated=true)` — 挂起在入口(先装 hook 再放行)
- `attach(pid_or_name)`
- `resume(pid)` / `detach(pid)` / `kill(pid)`
- `list_modules(pid)` / `list_exports(module)` / `list_imports(module)`
- `resolve_symbol(name)` / `find_export(module, name)`

### B. 内存

- `read_memory(addr, size, format=hex|utf8|...)`
- `write_memory(addr, bytes)`
- `scan_memory(pattern, ranges=...)` — AOB / 通配扫描
- `list_ranges(pid, protection)`

### C. Hook / 追踪

- `eval(pid, code)` — 常驻上下文执行 JS,返回结构化值(**核心**)
- `add_hook(target, on_enter?, on_leave?)` — Interceptor.attach 封装,
  落盘事件
- `trace_api(pattern)` — frida-trace 式批量 hook,如 `kernel32!CreateFile*`
- `replace_function(target, code)` — Interceptor.replace
- `list_hooks(pid)` / `remove_hook(id)`
- `backtrace(...)` — 调用栈

### D. 反汇编(精简)

- `disassemble(addr, count)` — Frida 内置 Capstone,反汇编活进程真实字节。
  仅做"读 N 条指令";xref / 函数边界 / 伪代码交给 IDA / x64dbg。

### 持久化 / 事件(贯穿 Persistent)

- `list_sessions()` — 历史会话(含死掉的)
- `resume_session(session_id)` — 进程活着则 re-attach,死了则提示 re-spawn
- `read_events(session_id, filter, range)` — 读已落盘的事件/trace(分页)
- `add_note(session_id, text)` / `list_notes`

## 5. 存储布局

一个"项目" = 一个目录:

```
<project>.fmcp/
├── db.sqlite                  # 元数据
└── traces/
    └── <session_id>.jsonl     # 流式事件(大块,append-only)
```

### SQLite 表(元数据)

- `sessions` — id, target(program/pid)、spawn 或 attach、创建时间、状态
  (alive/dead)、最后一次 attach 的可执行路径与参数(用于 re-spawn)、
  进程启动时间戳(防 pid 复用误判)。
- `instruments` — 当前生效的 hook/trace/replace:id、session_id、类型、
  target 表达式、**注入用的 JS 源码**(用于恢复重建)、状态。
- `repl_history` — session_id、code、结构化结果摘要(preview)、时间。
- `notes` — session_id、文本、时间。
- `events_index` — session_id、事件类型、行号/字节偏移 → 指向
  `traces/<id>.jsonl` 里的位置(支持分页读)。

### 文件(大块 trace)

- `traces/<session_id>.jsonl` — 常驻脚本每 `send()` 一条事件就**追加
  一行**。这是"边捕获边落盘、崩了不丢"的落点。

> 为什么事件用 JSONL 而非塞进 SQLite:trace 量可能很大且是顺序追加流,
> append-only 文件写入最便宜、最不易因崩溃损坏;SQLite 只存可查询的
> 元数据和索引。

## 6. 返回值结构(Scriptable 核心)

`eval` / hook 参数序列化成**带类型的结构 + preview**。常驻脚本里有一个
`serialize(value)` 函数,带**深度上限 + 数组长度上限**(可配),防止巨大
对象 / 环引用撑爆返回值。

```jsonc
// 指针
{ "type": "pointer", "value": "0x7ff6a0001234",
  "module": "game.exe", "offset": "0x1234",
  "symbol": "game.exe!update_player",   // 能解析就带上
  "preview": "0x7ff6a0001234 game.exe!update_player" }

// 数组 / 对象:递归展开(限深度+长度)
{ "type": "array", "length": 3,
  "items": [ /* ... */ ],
  "preview": "[3 items]" }

// ArrayBuffer / 内存块
{ "type": "bytes", "size": 64, "hex": "4889...", "preview": "<64 bytes>" }

// 基本类型直出
{ "type": "number", "value": 42, "preview": "42" }
```

对 agent 的意义:`eval` 返回一个 pointer 结构 → agent 直接拿 `value`
字段喂给 `disassemble` 或 `read_memory`,无需解析人类字符串。`preview`
字段用于写进 `repl_history` / 日志,人也看得懂。

## 7. 恢复流程(Persistent 闭环)

`resume_session(id)`:

1. 读 `sessions` 看目标是否还活着(按 pid + 进程启动时间戳核对,防 pid
   复用)。
2. **活着** → re-attach,重新注入常驻脚本,然后按 `instruments` 表里存的
   JS 源码把 hook 逐个重装,恢复现场。
3. **死了** → 用 `sessions` 里存的可执行路径 / 参数提示 agent 可 `spawn`
   重建,重装同样的 instruments。
4. 历史 `read_events` / `repl_history` / `notes` 无论死活都能读(已落盘)。

## 8. 模块划分(便于隔离与测试)

- `mcp_tools/` — MCP 工具定义层,薄封装,只做参数校验 + 调 SessionManager。
- `session.py`(SessionManager)— 进程会话与常驻脚本生命周期、恢复流程。
- `store.py` — SQLite + JSONL 持久化,event 流式写入与分页读。
- `agent.js`(常驻脚本)— rpc.exports(eval / hook 注册)+ serialize +
  send 事件。
- `serialize` 约定 — Python 端与 JS 端共享的结构化值 schema。

每个单元职责单一、通过明确接口通信,可独立理解和测试。

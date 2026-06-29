'use strict';

// Frida 17.x removed the static Module.getExportByName(mod, name) form.
// Patch it back so resolveTarget() and inline eval strings keep working.
if (typeof Module.getExportByName !== 'function') {
  Module.getExportByName = function (mod, name) {
    if (mod === null || mod === undefined) return Module.getGlobalExportByName(name);
    return Process.getModuleByName(mod).getExportByName(name);
  };
}

if (typeof Module.enumerateExports !== 'function') {
  Module.enumerateExports = function (name) {
    return Process.getModuleByName(name).enumerateExports();
  };
}

const MAX_DEPTH = 3;
const MAX_ARRAY = 50;
const MAX_KEYS = 50;

function describePointer(ptr) {
  const out = { type: 'pointer', value: ptr.toString() };
  try {
    const m = Process.findModuleByAddress(ptr);
    if (m) {
      out.module = m.name;
      out.offset = '0x' + ptr.sub(m.base).toString(16);
    }
    const sym = DebugSymbol.fromAddress(ptr);
    if (sym && sym.name) {
      out.symbol = (sym.moduleName ? sym.moduleName + '!' : '') + sym.name;
    }
  } catch (e) {}
  out.preview = out.value + (out.symbol ? ' ' + out.symbol : '');
  return out;
}

function serialize(value, depth) {
  if (depth > MAX_DEPTH) return { type: 'truncated', preview: '<max depth>' };
  if (value === null || value === undefined) {
    return { type: 'null', preview: 'null' };
  }
  if (value instanceof NativePointer) return describePointer(value);
  if (value instanceof ArrayBuffer) {
    const bytes = new Uint8Array(value);
    const hex = Array.from(bytes.slice(0, 64))
      .map((b) => ('0' + b.toString(16)).slice(-2)).join('');
    return { type: 'bytes', size: bytes.length, hex,
             preview: '<' + bytes.length + ' bytes>' };
  }
  const t = typeof value;
  if (t === 'number' || t === 'bigint') {
    return { type: 'number', value: Number(value), preview: String(value) };
  }
  if (t === 'boolean') return { type: 'boolean', value, preview: String(value) };
  if (t === 'string') {
    return { type: 'string', value, preview: JSON.stringify(value) };
  }
  if (t === 'function') return { type: 'function', preview: '[function]' };
  if (Array.isArray(value)) {
    const items = value.slice(0, MAX_ARRAY).map((v) => serialize(v, depth + 1));
    return { type: 'array', length: value.length, items,
             preview: '[' + value.length + ' items]' };
  }
  if (t === 'object') {
    const keys = {};
    let n = 0;
    for (const k of Object.keys(value)) {
      if (n++ >= MAX_KEYS) break;
      try { keys[k] = serialize(value[k], depth + 1); }
      catch (e) { keys[k] = { type: 'null', preview: '<error>' }; }
    }
    return { type: 'object', keys, preview: '{' + Object.keys(value).length + ' keys}' };
  }
  return { type: 'null', preview: String(value) };
}

function resolveTarget(expr) {
  if (expr.indexOf('!') !== -1) {
    const [mod, name] = expr.split('!');
    return Module.getExportByName(mod, name);
  }
  return ptr(expr);
}

const hooks = {};
let hookSeq = 0;

function installHook(target, addr) {
  const id = ++hookSeq;
  const listener = Interceptor.attach(addr, {
    onEnter(args) {
      const captured = [];
      for (let i = 0; i < 4; i++) captured.push(serialize(args[i], 1));
      let bt = [];
      try {
        bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
          .slice(0, 8).map((a) => describePointer(a).preview);
      } catch (e) {}
      send({ type: 'hook', id, target, args: captured, backtrace: bt });
    },
  });
  hooks[id] = { target, listener };
  return id;
}

rpc.exports = {
  evaluate(code) {
    try {
      const result = (0, eval)(code);  // indirect eval → global scope
      return serialize(result, 0);
    } catch (e) {
      return { type: 'string', value: 'ERROR: ' + e,
               preview: 'ERROR: ' + e };
    }
  },
  addHook(targetExpr) {
    try {
      return { id: installHook(targetExpr, resolveTarget(targetExpr)) };
    } catch (e) {
      return { error: String(e) };
    }
  },
  removeHook(id) {
    const h = hooks[id];
    if (!h) return false;
    h.listener.detach();
    delete hooks[id];
    return true;
  },
  listHooks() {
    return Object.keys(hooks).map((id) => ({ id: Number(id), target: hooks[id].target }));
  },
  traceApi(pattern) {
    try {
      const [mod, glob] = pattern.split('!');
      if (!glob) return { ids: [], matched: 0 };
      const re = new RegExp('^' + glob.replace(/[.+^${}()|[\]\\]/g, '\\$&')
        .replace(/\*/g, '.*').replace(/\?/g, '.') + '$');
      const ids = [];
      for (const exp of Module.enumerateExports(mod)) {
        if (exp.type === 'function' && re.test(exp.name)) {
          if (ids.length >= 200) break;
          ids.push(installHook(mod + '!' + exp.name, exp.address));
        }
      }
      return { ids, matched: ids.length };
    } catch (e) {
      return { error: String(e) };
    }
  },
  replaceFunction(targetExpr, code) {
    try {
      const addr = resolveTarget(targetExpr);
      const cb = (0, eval)('(' + code + ')');
      const id = ++hookSeq;
      const native = new NativeCallback(cb, 'pointer', ['pointer', 'pointer']);
      Interceptor.replace(addr, native);
      hooks[id] = { target: targetExpr, listener: { detach() { Interceptor.revert(addr); } } };
      return { id };
    } catch (e) {
      return { error: String(e) };
    }
  },
  readMemory(addr, size) {
    try {
      return { hex: hexdumpRaw(ptr(addr), size) };
    } catch (e) {
      return { error: String(e) };
    }
  },
  writeMemory(addr, hex) {
    try {
      const bytes = [];
      for (let i = 0; i < hex.length; i += 2) bytes.push(parseInt(hex.substr(i, 2), 16));
      ptr(addr).writeByteArray(bytes);
      return { written: bytes.length };
    } catch (e) {
      return { error: String(e) };
    }
  },
  scanMemory(pattern, protection) {
    try {
      const hits = [];
      for (const range of Process.enumerateRanges(protection || 'r--')) {
        if (hits.length >= 256) break;
        const found = Memory.scanSync(range.base, range.size, pattern);
        for (const m of found) {
          if (hits.length >= 256) break;
          hits.push(describePointer(m.address));
        }
      }
      return hits;
    } catch (e) {
      return { error: String(e) };
    }
  },
  disassemble(addr, count) {
    try {
      const out = [];
      let cur = ptr(addr);
      for (let i = 0; i < count; i++) {
        const insn = Instruction.parse(cur);
        out.push({ address: cur.toString(), mnemonic: insn.mnemonic,
                   opStr: insn.opStr, size: insn.size });
        cur = insn.next;
      }
      return out;
    } catch (e) {
      return { error: String(e) };
    }
  },
};

function hexdumpRaw(p, size) {
  const bytes = new Uint8Array(p.readByteArray(size));
  return Array.from(bytes).map((b) => ('0' + b.toString(16)).slice(-2)).join('');
}

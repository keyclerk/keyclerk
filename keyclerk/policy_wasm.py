# SPDX-License-Identifier: EUPL-1.2
"""Policies evaluated in process: Rego compiled to WebAssembly, run with wasmtime (decision 0008).

KeyClerk runs on its own: no policy server, no network for a decision. The engine gathers facts in Python and asks
the compiled policy, which is the one definition of the rule (the same Rego that OPA tests). This is the OPA
WebAssembly ABI's fast path: the input JSON is written into the module's memory, opa_eval runs one entrypoint and
returns the result set as JSON. The policies use no builtin that needs a host function; one that did would fail
loudly when loaded, never silently at a decision.
"""
from __future__ import annotations

import atexit
import json
import threading
from collections import OrderedDict
from pathlib import Path

POLICY = Path(__file__).resolve().parent / "policy"
PAGE = 65536


class Policy:
    def __init__(self, wasm: bytes):
        from wasmtime import Engine, FuncType, Limits, Linker, Memory, MemoryType, Module, Store, ValType
        self._lock = threading.Lock()
        self.engine = Engine()
        self.store = Store(self.engine)
        self.mem = Memory(self.store, MemoryType(Limits(4, None)))
        linker = Linker(self.engine)
        linker.define(self.store, "env", "memory", self.mem)
        i32 = ValType.i32()

        def abort(addr):
            raise RuntimeError("policy aborted: " + self._cstr(addr)[:300])

        linker.define_func("env", "opa_abort", FuncType([i32], []), abort)
        linker.define_func("env", "opa_println", FuncType([i32], []), lambda addr: None)
        for n in range(5):
            def missing(*a, _n=n):
                raise RuntimeError("the policy calls a builtin this engine does not provide")
            linker.define_func("env", f"opa_builtin{n}", FuncType([i32] * (n + 2), [i32]), missing)
        self.ex = linker.instantiate(self.store, Module(self.engine, wasm)).exports(self.store)
        if self._value(self.ex["builtins"](self.store)):
            raise RuntimeError("the policy needs host builtins; this engine provides none")
        self.entrypoints = self._value(self.ex["entrypoints"](self.store))
        self.data = self._parse(b"{}")
        self.heap = self.ex["opa_heap_ptr_get"](self.store)

    def close(self) -> None:
        """Free in dependency order: exports and memory, then the store, then the engine. Left to the garbage
        collector at interpreter exit, the store can be freed after what refers to it (an access violation)."""
        with self._lock:
            self.ex = self.mem = None
            if self.store is not None:
                self.store.close()
                self.store = None
            if self.engine is not None:
                self.engine.close()
                self.engine = None

    # --- memory ---------------------------------------------------------------------------------------------------

    def _cstr(self, addr: int) -> str:
        out, step = bytearray(), 4096
        while True:
            chunk = self.mem.read(self.store, addr, min(addr + step, self.mem.data_len(self.store)))
            i = chunk.find(b"\0")
            if i >= 0:
                out += chunk[:i]
                return out.decode("utf-8")
            out += chunk
            addr += len(chunk)

    def _write(self, data: bytes) -> int:
        addr = self.ex["opa_malloc"](self.store, len(data))
        self._room(addr + len(data))
        self.mem.write(self.store, data, addr)
        return addr

    def _room(self, end: int) -> None:
        have = self.mem.data_len(self.store)
        if end + PAGE > have:
            self.mem.grow(self.store, (end + PAGE - have) // PAGE + 1)

    def _parse(self, raw: bytes) -> int:
        return self.ex["opa_json_parse"](self.store, self._write(raw), len(raw))

    def _value(self, addr: int):
        return json.loads(self._cstr(self.ex["opa_json_dump"](self.store, addr)))

    # --- evaluation -----------------------------------------------------------------------------------------------

    CACHE_SIZE = 8192

    def eval(self, entrypoint: str, input_doc) -> object:
        """The value of one entrypoint for this input (the first result of the result set). The data is fixed at load,
        so an answer depends only on entrypoint and input: answers are kept per exact input (decision 0017; one check
        asks the identity policy thousands of times with a handful of distinct inputs). Each caller gets its own copy."""
        raw = json.dumps(input_doc, separators=(",", ":"), sort_keys=True).encode("utf-8")
        key = (entrypoint, raw)
        with self._lock:
            cache = self.__dict__.setdefault("_cache", OrderedDict())
            hit = cache.get(key)
            if hit is not None:
                cache.move_to_end(key)
                return json.loads(hit)
        out = self._eval_raw(entrypoint, raw)
        with self._lock:
            cache[key] = json.dumps(out)
            if len(cache) > self.CACHE_SIZE:
                cache.popitem(last=False)
        return out

    def _eval_raw(self, entrypoint: str, raw: bytes) -> object:
        with self._lock:
            self.ex["opa_heap_ptr_set"](self.store, self.heap)
            self._room(self.heap + len(raw) + 1024 * 1024)
            self.mem.write(self.store, raw, self.heap)
            res = self.ex["opa_eval"](self.store, 0, self.entrypoints[entrypoint], self.data, self.heap, len(raw),
                                      self.heap + len(raw), 0)
            out = json.loads(self._cstr(res))
        return out[0]["result"] if out else None


_LOADED: dict[str, Policy] = {}
_LOAD_LOCK = threading.Lock()


def load(name: str) -> Policy:
    with _LOAD_LOCK:
        if name not in _LOADED:
            _LOADED[name] = Policy((POLICY / f"{name}.wasm").read_bytes())
        return _LOADED[name]


@atexit.register
def _close_all() -> None:
    """Free the modules while wasmtime is still loaded, in order, not during interpreter teardown."""
    with _LOAD_LOCK:
        for pol in _LOADED.values():
            pol.close()
        _LOADED.clear()


def second_key(candidates: list[dict], policy: dict) -> dict:
    """keyclerk/policy/second_key.rego: which approvers count, under the policy's mode, and why the others do not."""
    return load("second_key").eval("keyclerk/second_key/decision", {"candidates": candidates, "policy": policy})


def view(viewer: dict, subject: dict, nodes: list[dict]) -> dict:
    """keyclerk/policy/view.rego: whether the viewer may see this person, which nodes, and the realm summary."""
    return load("view").eval("keyclerk/view/decision", {"viewer": viewer, "subject": subject, "nodes": nodes})


def tree(viewer: dict, nodes: list[dict]) -> dict:
    """keyclerk/policy/tree.rego: which delegations of the tree the viewer may see."""
    return load("tree").eval("keyclerk/tree/decision", {"viewer": viewer, "nodes": nodes})


def visits(decision: str, input_doc: dict):
    """keyclerk/policy/visits.rego: act, entry, timers or see (decision 0009)."""
    return load("visits").eval(f"keyclerk/visits/{decision}", input_doc)


def identity(decision: str, input_doc: dict):
    """keyclerk/policy/identity.rego: membership or reach (decision 0011)."""
    return load("identity").eval(f"keyclerk/identity/{decision}", input_doc)


def ceiling(input_doc: dict) -> dict:
    """keyclerk/policy/ceiling.rego: what an edge's signed ceiling allows (decision 0014)."""
    return load("ceiling").eval("keyclerk/ceiling/decision", input_doc)


def edge(decision: str, input_doc: dict):
    """keyclerk/policy/edge.rego: settings, admit or visit_window (decision 0014); the module an edge agent runs too."""
    return load("edge").eval(f"keyclerk/edge/{decision}", input_doc)

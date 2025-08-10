

"""
https://github.com/Avimuller1102

merkle-run: tamper-evident, deterministic runner for python scripts (no root)

usage:
  python merklerun.py run path/to/target.py --args "foo bar" --seed 42 --allow-net 0
  python merklerun.py verify path/to/target.py manifest.json --seed 42 --allow-net 0
  python merklerun.py diff manifest_a.json manifest_b.json
"""

import argparse
import builtins
import functools
import hashlib
import importlib.util
import io
import json
import os
import random
import runpy
import socket
import subprocess
import sys
import time
import types
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

# ------------------------------
# event logger with merkle chain
# ------------------------------


class EventLogger:
    # all comments are in lowercase on purpose, as requested.
    def __init__(self, seed: int, allow_net: bool):
        # start timestamp and monotonic base for stable timing deltas
        self.start_wall = datetime.utcnow().isoformat() + "Z"
        self.start_mono = time.monotonic()
        self.events: List[Dict[str, Any]] = []
        self.prev_hash = "0" * 64
        self.seed = seed
        self.allow_net = allow_net
        # capture minimal environment snapshot for context
        self.env = {
            "python_version": sys.version,
            "platform": sys.platform,
            "cwd": os.getcwd(),
        }

    def _hash_dict(self, d: Dict[str, Any]) -> str:
        # hash json deterministically
        payload = json.dumps(d, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(payload).hexdigest()

    def _chain(self, event: Dict[str, Any]) -> str:
        # add merkle-like chaining by hashing previous hash + event hash
        h_event = self._hash_dict(event)
        combined = (self.prev_hash + h_event).encode()
        h_chain = hashlib.sha256(combined).hexdigest()
        self.prev_hash = h_chain
        return h_chain

    def log(self, kind: str, **fields):
        # compute relative time for readability
        rel = time.monotonic() - self.start_mono
        event = {"t": round(rel, 6), "kind": kind, **fields}
        h = self._chain(event)
        event["chain"] = h
        self.events.append(event)

    def manifest(self) -> Dict[str, Any]:
        # build final manifest with a root hash
        root = {
            "started_at_utc": self.start_wall,
            "seed": self.seed,
            "allow_net": self.allow_net,
            "env": self.env,
            "events": self.events,
        }
        root["root_hash"] = self._hash_dict({"events": self.events})
        return root
    

# -----------------------------------
# monkeypatches for io/net/subprocess
# -----------------------------------

class IOShim:
    # a file wrapper that updates a hasher on writes and records size
    def __init__(self, f, path, mode, logger: EventLogger):
        self._f = f
        self._path = path
        self._mode = mode
        self._logger = logger
        self._written = 0
        self._hasher = hashlib.sha256()

    def write(self, b):
        # support str and bytes
        if isinstance(b, str):
            b = b.encode()
        self._written += len(b)
        self._hasher.update(b)
        return self._f.write(b)

    def writelines(self, lines):
        # collect everything through write for hashing
        total = 0
        for line in lines:
            total += self.write(line)
        return total

    def close(self):
        try:
            return self._f.close()
        finally:
            if "w" in self._mode or "a" in self._mode or "x" in self._mode:
                self._logger.log(
                    "file_write_close",
                    path=os.path.abspath(self._path),
                    bytes=self._written,
                    sha256=self._hasher.hexdigest(),
                )

    def __getattr__(self, name):
        # forward other attributes (read, flush, etc.)
        return getattr(self._f, name)

def hash_file(path: str) -> Tuple[int, str]:
    # hash file content without loading all in memory
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as rf:
        while True:
            chunk = rf.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            h.update(chunk)
    return size, h.hexdigest()

def patch_open(logger: EventLogger):
    original_open = builtins.open

    def open_wrapper(path, mode="r", *args, **kwargs):
        abspath = os.path.abspath(path)
        # on read, hash the current file content immediately (determinism)
        if "r" in mode and os.path.exists(abspath) and "b" in mode:
            size, sha = hash_file(abspath)
            logger.log("file_open_read", path=abspath, mode=mode, bytes=size, sha256=sha)
        elif "r" in mode and os.path.exists(abspath) and "b" not in mode:
            # if text mode read, still compute hash on bytes for stability
            size, sha = hash_file(abspath)
            logger.log("file_open_read", path=abspath, mode=mode, bytes=size, sha256=sha)
        else:
            logger.log("file_open", path=abspath, mode=mode)

        f = original_open(path, mode, *args, **kwargs)
        # if writing, wrap to collect hash of written bytes
        if any(m in mode for m in ("w", "a", "x")):
            return IOShim(f, path, mode, logger)
        return f

    builtins.open = open_wrapper
    return original_open

def patch_socket(logger: EventLogger, allow_net: bool):
    original_socket = socket.socket

    class SocketShim(socket.socket):
        def connect(self, address):
            # block or log network according to policy
            host, port = address[0], address[1]
            if not allow_net:
                logger.log("net_block", host=host, port=port)
                raise PermissionError("network disabled by merkle-run")
            logger.log("net_connect", host=host, port=port)
            return super().connect(address)

        def send(self, data, *args, **kwargs):
            if not allow_net:
                logger.log("net_block_send", bytes=len(data))
                raise PermissionError("network disabled by merkle-run")
            sha = hashlib.sha256(data if isinstance(data, (bytes, bytearray)) else str(data).encode()).hexdigest()
            logger.log("net_send", bytes=len(data), sha256=sha)
            return super().send(data, *args, **kwargs)

        def recv(self, bufsize, *args, **kwargs):
            if not allow_net:
                logger.log("net_block_recv", req=bufsize)
                raise PermissionError("network disabled by merkle-run")
            data = super().recv(bufsize, *args, **kwargs)
            sha = hashlib.sha256(data).hexdigest()
            logger.log("net_recv", bytes=len(data), sha256=sha)
            return data

    socket.socket = SocketShim
    return original_socket

def patch_subprocess(logger: EventLogger):
    original_popen = subprocess.Popen

    class PopenShim(subprocess.Popen):
        def __init__(self, args, *pargs, **kwargs):
            # normalize args to a printable form
            cmd = args if isinstance(args, list) else [str(args)]
            logger.log("subprocess_spawn", cmd=" ".join(map(str, cmd)))
            super().__init__(args, *pargs, **kwargs)

    subprocess.Popen = PopenShim
    return original_popen

def seed_all(seed: int, logger: EventLogger):
    # fix python's prng; try numpy if present
    random.seed(seed)
    logger.log("rng_seed", lib="random", seed=seed)
    try:
        import numpy as np  # type: ignore
        np.random.seed(seed)
        logger.log("rng_seed", lib="numpy", seed=seed)
    except Exception:
        logger.log("rng_seed_skip", lib="numpy")

# ----------------
# core run/verify
# ----------------

def run_instrumented(target: str, args_line: Optional[str], seed: int, allow_net: bool) -> Dict[str, Any]:
    logger = EventLogger(seed=seed, allow_net=allow_net)

    # apply patches
    undo_open = patch_open(logger)
    undo_sock = patch_socket(logger, allow_net)
    undo_popen = patch_subprocess(logger)
    seed_all(seed, logger)

    # prepare argv for the target script
    old_argv = sys.argv[:]
    sys.argv = [target] + (args_line.split() if args_line else [])

    try:
        # run the target in its own globals using runpy
        logger.log("begin", target=os.path.abspath(target), args=sys.argv[1:])
        runpy.run_path(target, run_name="__main__")
        logger.log("end", status="ok")
    except Exception as e:
        # log exception type and message (not stack) to keep manifest stable
        logger.log("end", status="exception", error=repr(e))
        raise
    finally:
        # restore patches
        builtins.open = undo_open
        socket.socket = undo_sock
        subprocess.Popen = undo_popen
        sys.argv = old_argv

    return logger.manifest()

def verify_run(target: str, ref_manifest_path: str, seed: int, allow_net: bool) -> Dict[str, Any]:
    # load reference manifest
    with open(ref_manifest_path, "r", encoding="utf-8") as f:
        ref = json.load(f)

    now = run_instrumented(target, args_line=" ".join(ref.get("events", [{}])[0].get("args", [])) if ref.get("events") else None,
                           seed=seed, allow_net=allow_net)

    # compare event sequence shape and critical fields
    diffs = []
    a, b = ref["events"], now["events"]
    n = min(len(a), len(b))
    for i in range(n):
        ea, eb = a[i], b[i]
        if ea["kind"] != eb["kind"]:
            diffs.append({"index": i, "field": "kind", "ref": ea["kind"], "now": eb["kind"]})
            continue
        # compare selected fields when present
        for key in ("path", "sha256", "bytes", "cmd", "host", "port"):
            va, vb = ea.get(key), eb.get(key)
            if va != vb:
                diffs.append({"index": i, "field": key, "ref": va, "now": vb})
    if len(a) != len(b):
        diffs.append({"index": "len", "ref": len(a), "now": len(b)})

    return {"ok": len(diffs) == 0, "diffs": diffs, "reference_root": ref.get("root_hash"), "now_root": now.get("root_hash")}

# ------------
# handy cli
# ------------

def main():
    parser = argparse.ArgumentParser(description="merkle-run: deterministic, tamper-evident runner")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_run = sub.add_parser("run", help="run a script and emit manifest.json")
    p_run.add_argument("target")
    p_run.add_argument("--args", default=None, help="args passed to target script (single string)")
    p_run.add_argument("--seed", type=int, default=1337)
    p_run.add_argument("--allow-net", type=int, default=0)
    p_run.add_argument("--out", default="manifest.json")

    p_ver = sub.add_parser("verify", help="re-run script and compare against a reference manifest")
    p_ver.add_argument("target")
    p_ver.add_argument("reference_manifest")
    p_ver.add_argument("--seed", type=int, default=1337)
    p_ver.add_argument("--allow-net", type=int, default=0)

    p_diff = sub.add_parser("diff", help="compare two manifests")
    p_diff.add_argument("a")
    p_diff.add_argument("b")

    args = parser.parse_args()

    if args.cmd == "run":
        manifest = run_instrumented(args.target, args.args, seed=args.seed, allow_net=bool(args.allow_net))
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, sort_keys=True)
        print(f"wrote {args.out} with root_hash {manifest['root_hash']}")
    elif args.cmd == "verify":
        result = verify_run(args.target, args.reference_manifest, seed=args.seed, allow_net=bool(args.allow_net))
        print(json.dumps(result, indent=2, sort_keys=True))
        if not result["ok"]:
            sys.exit(2)
    elif args.cmd == "diff":
        with open(args.a, "r", encoding="utf-8") as fa, open(args.b, "r", encoding="utf-8") as fb:
            A, B = json.load(fa), json.load(fb)
        print("root a:", A.get("root_hash"))
        print("root b:", B.get("root_hash"))
        # simple diff by event count and kinds
        kinds_a = [e["kind"] for e in A.get("events", [])]
        kinds_b = [e["kind"] for e in B.get("events", [])]
        print("len a:", len(kinds_a), "len b:", len(kinds_b))
        for i, (ka, kb) in enumerate(zip(kinds_a, kinds_b)):
            if ka != kb:
                print(f"@{i}: {ka} != {kb}")

if __name__ == "__main__":
    main()

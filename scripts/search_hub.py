"""On-demand federated Spiffy Search without a second search index.

Quick mode queries the existing file-index agent (if running) and current
Spiffy Shelf's *saved title* metadata authority. Deep mode adds the existing
MemoryCore lexical search. Voice Archive transcripts are already indexed by
MemoryCore; "voice" requests its exact source family. Clipboard content/history
is deliberately NOT duplicated or queried through an unauthenticated path.

This tool has no daemon, new DB, hotkey or startup task. It never starts an
agent, builds an index, changes permissions, caches a query, stores memory
results or sends search text to a web API. Results print to the invoking
terminal only. NDJSON mode emits each source as it completes so slow MemoryCore
imports cannot block the initial file/Shelf result.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Callable, Mapping, Any

MAX_QUERY_UTF8 = 512
MAX_CAPTURE = 2 * 1024 * 1024
MAX_RESULTS = 20
FAST_TIMEOUT = 3.0
MEMORY_TIMEOUT = 23.0
SOURCES = ("files", "shelf", "memory", "voice")


@dataclass(frozen=True)
class Paths:
    searchctl: Path
    memory_root: Path
    memory_receipt: Path
    search_endpoint: Path | None = None

    @classmethod
    def defaults(cls) -> "Paths":
        local = Path(os.environ.get("LOCALAPPDATA", ""))
        if not local.is_absolute():
            raise ValueError("LOCALAPPDATA is unavailable; no source will run")
        base = Path(__file__).resolve().parents[2]
        return cls(
            searchctl=local / "Programs" / "SpiffySearch" / "spiffy-searchctl.exe",
            memory_root=base / "MemoryCore",
            memory_receipt=local / "MemoryCore" / "host-runtime-current.json",
            search_endpoint=local / "SpiffySearch" / "ipc-endpoint.json",
        )


def parse_sources(value: str) -> tuple[str, ...]:
    text = value.strip().lower()
    if text == "quick":
        return ("files", "shelf")
    if text == "all":
        # MemoryCore already includes Voice Archive documents. Querying both
        # would duplicate results and run two expensive Python imports.
        return ("files", "shelf", "memory")
    values = tuple(dict.fromkeys(part.strip() for part in text.split(",")))
    if not values or any(part not in SOURCES for part in values):
        raise ValueError("Sources must be quick, all, or comma-separated files/shelf/memory/voice")
    if "voice" in values and "memory" in values:
        raise ValueError("Use memory OR voice, not both: one MemoryCore search covers Voice Archive")
    return values


def validate_query(query: str, limit: int) -> None:
    if not isinstance(query, str) or not query.strip():
        raise ValueError("Search query cannot be empty")
    if "\x00" in query or any(ord(ch) < 32 and ch not in "\t\n" for ch in query):
        raise ValueError("Search query contains unsupported control characters")
    if len(query.encode("utf-8")) > MAX_QUERY_UTF8:
        raise ValueError(f"Search query exceeds {MAX_QUERY_UTF8} UTF-8 bytes")
    if type(limit) is not int or not 1 <= limit <= MAX_RESULTS:
        raise ValueError(f"Result limit must be 1..{MAX_RESULTS}")


def memory_python(paths: Paths) -> Path | None:
    """Use MemoryCore's promoted owner interpreter, not a guessed system Python."""
    try:
        meta = json.loads(paths.memory_receipt.read_text(encoding="utf-8-sig"))
        binary = Path(meta["python"])
        expected_hash = meta["python_sha256"]
    except (OSError, ValueError, KeyError, TypeError):
        return None
    if (meta.get("schema") != "memorycore_host_runtime_ref_v1"
            or not isinstance(expected_hash, str)
            or len(expected_hash) != 64
            or any(ch not in "0123456789abcdef" for ch in expected_hash.lower())):
        return None
    # The receipt itself is an existing MemoryCore-managed identity; refuse
    # paths outside its own runtime root instead of executing arbitrary code.
    expected_root = paths.memory_receipt.parent / "runtimes"
    try:
        if not binary.is_file() or not binary.resolve().is_relative_to(expected_root.resolve()):
            return None
    except (OSError, RuntimeError, ValueError):
        return None
    # Reuse the canonical MemoryCore wrapper's sealed interpreter digest.
    # Never launch an unqualified interpreter just because its path exists.
    try:
        hasher = hashlib.sha256()
        with binary.open("rb") as fh:
            for block in iter(lambda: fh.read(1024 * 1024), b""):
                hasher.update(block)
        if hasher.hexdigest() != expected_hash.lower():
            return None
    except OSError:
        return None
    return binary


def command_for(source: str, query: str, limit: int, paths: Paths) -> tuple[list[str], Path | None, float] | None:
    if source in {"files", "shelf"}:
        if not paths.searchctl.is_file():
            return None
        args = ([str(paths.searchctl), "--json", "search", query, "--limit", str(limit)]
                if source == "files" else
                [str(paths.searchctl), "--json", "shelf", "search", query, "--limit", str(limit)])
        return args, None, FAST_TIMEOUT
    if source in {"memory", "voice"}:
        py = memory_python(paths)
        if py is None or not (paths.memory_root / "memorycore" / "__main__.py").is_file():
            return None
        # --no-store makes MemoryCore use its canonical read-only DB path.
        # Never turn on --related-meaning or download an encoder implicitly.
        text = f"source:voicearchive {query}" if source == "voice" else query
        args = [str(py), "-B", "-m", "memorycore", "search", text,
                "--limit", str(limit), "--no-store", "--scope", "personal"]
        return args, paths.memory_root, MEMORY_TIMEOUT
    raise ValueError("Unsupported owner")


def _run_command(
    args: list[str], cwd: Path | None, timeout: float, env: Mapping[str, str] | None = None
) -> tuple[int, bytes, bytes]:
    environment = os.environ.copy()
    environment["PYTHONNOUSERSITE"] = "1"
    if env:
        environment.update(env)
    completed = subprocess.run(
        args, cwd=cwd, env=environment,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=timeout, check=False,
        creationflags=(subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0),
    )
    return completed.returncode, completed.stdout[:MAX_CAPTURE + 1], completed.stderr[:MAX_CAPTURE + 1]


def _count_rows(source: str, data: Any) -> int:
    if not isinstance(data, dict):
        return 0
    if source == "files":
        obj = data.get("data")
        return len(obj.get("hits", [])) if isinstance(obj, dict) and isinstance(obj.get("hits"), list) else 0
    if source == "shelf":
        obj = data.get("data")
        return len(obj.get("results", [])) if isinstance(obj, dict) and isinstance(obj.get("results"), list) else 0
    values = data.get("results")
    return len(values) if isinstance(values, list) else 0


def query_owner(
    source: str, query: str, limit: int, paths: Paths,
    runner: Callable[..., tuple[int, bytes, bytes]] = _run_command,
) -> dict[str, Any]:
    started = time.perf_counter()
    if source == "files" and paths.search_endpoint is not None:
        # Saved-Shelf title search does NOT require this daemon. When the
        # private Search endpoint is absent, spawning the installed file CLI
        # just to discover it is stopped costs ~140 ms on this workstation.
        # Query only its own private endpoint's existence, never its token.
        try:
            endpoint = paths.search_endpoint
            if endpoint.is_symlink() or not endpoint.is_file():
                return {"source": source, "status": "unavailable", "rows": 0,
                        "latency_ms": round((time.perf_counter() - started) * 1000, 2),
                        "reason": "agent_not_running"}
        except OSError:
            return {"source": source, "status": "unavailable", "rows": 0,
                    "latency_ms": round((time.perf_counter() - started) * 1000, 2),
                    "reason": "agent_endpoint_inaccessible"}
    planned = command_for(source, query, limit, paths)
    if planned is None:
        return {"source": source, "status": "unavailable", "rows": 0, "latency_ms": 0,
                "reason": "owner_install_unavailable"}
    args, cwd, timeout = planned
    try:
        code, stdout, stderr = runner(args, cwd, timeout)
        if len(stdout) > MAX_CAPTURE or len(stderr) > MAX_CAPTURE:
            raise ValueError("owner reply exceeded its response budget")
        if code:
            # Do not echo stderr: it can include sensitive names or query text.
            return {"source": source, "status": "unavailable", "rows": 0,
                    "latency_ms": round((time.perf_counter() - started) * 1000, 2),
                    "reason": "owner_process_exited"}
        obj = json.loads(stdout.decode("utf-8-sig"))
        if not isinstance(obj, dict) or obj.get("ok") is not True:
            raise ValueError("owner returned an invalid or negative response")
        return {"source": source, "status": "ready",
                "rows": _count_rows(source, obj),
                "latency_ms": round((time.perf_counter() - started) * 1000, 2),
                "owner_response": obj}
    except subprocess.TimeoutExpired:
        status, reason = "timeout", "owner_deadline_exceeded"
    except (UnicodeError, ValueError, OSError):
        status, reason = "error", "owner_response_invalid"
    return {"source": source, "status": status, "rows": 0,
            "latency_ms": round((time.perf_counter() - started) * 1000, 2),
            "reason": reason}


def iter_results(query: str, sources: tuple[str, ...], limit: int, paths: Paths,
                 runner: Callable[..., tuple[int, bytes, bytes]] = _run_command):
    # Each source is independent: the first fast owner can produce a result
    # without a cold 17-second MemoryCore Python import blocking the UI.
    with ThreadPoolExecutor(max_workers=len(sources)) as executor:
        tasks = {executor.submit(query_owner, s, query, limit, paths, runner): s for s in sources}
        for future in as_completed(tasks):
            yield future.result()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("query", help="Literal private local search query (never logged)")
    parser.add_argument("--sources", default="quick", help="quick [default], all, or files,shelf,memory,voice")
    parser.add_argument("--limit", type=int, default=8)
    parser.add_argument("--stream", action="store_true", help="Emit one NDJSON event immediately when each owner replies")
    parser.add_argument("--diagnostics", action="store_true",
                        help="Hide owner result content; report status, counts and timing only")
    args = parser.parse_args(argv)
    try:
        sources = parse_sources(args.sources)
        validate_query(args.query, args.limit)
        paths = Paths.defaults()
    except ValueError as error:
        parser.error(str(error))
    reports = []
    for report in iter_results(args.query, sources, args.limit, paths):
        if args.diagnostics:
            report = {k: v for k, v in report.items() if k != "owner_response"}
        if args.stream:
            print(json.dumps(report, ensure_ascii=False), flush=True)
        reports.append(report)
    if not args.stream:
        print(json.dumps({"schema": "spiffy_search_hub_v1", "sources": reports,
                          "clipboard_owner": "native Spiffy Clipboard UI; no history copied",
                          "has_live_file_agent": any(x["source"] == "files" and x["status"] == "ready" for x in reports)},
                         ensure_ascii=False))
    return 0 if any(x["status"] == "ready" for x in reports) else 1


if __name__ == "__main__":
    raise SystemExit(main())

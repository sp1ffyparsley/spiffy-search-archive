"""No-production-data tests for the on-demand read-only Search Hub."""
from __future__ import annotations

import importlib.util
import hashlib
import json
from pathlib import Path
import subprocess
import threading
import time
import unittest

FILE=Path(__file__).with_name("search_hub.py")
SPEC=importlib.util.spec_from_file_location("search_hub",FILE)
hub=importlib.util.module_from_spec(SPEC)
import sys
sys.modules[SPEC.name]=hub
SPEC.loader.exec_module(hub)


class SearchHubTests(unittest.TestCase):
    def setUp(self):
        from tempfile import TemporaryDirectory
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        d = Path(self.tmp.name)
        (d / "spiffy-searchctl.exe").touch()
        self.memory = d / "MemoryCore"
        (self.memory / "memorycore").mkdir(parents=True)
        (self.memory / "memorycore" / "__main__.py").touch()
        self.runtime = d / "MemoryRuntime"
        (self.runtime / "runtimes").mkdir(parents=True)
        (self.runtime / "runtimes" / "python.exe").touch()
        self.receipt = self.runtime / "host-runtime-current.json"
        self.receipt.write_text(json.dumps({
            "schema": "memorycore_host_runtime_ref_v1",
            "python": str(self.runtime / "runtimes" / "python.exe"),
            "python_sha256": hashlib.sha256(b"").hexdigest(),
        }))
        self.paths = hub.Paths(d / "spiffy-searchctl.exe",self.memory,self.receipt)

    def test_mode_admission_and_privacy(self):
        self.assertEqual(hub.parse_sources("quick"),("files","shelf"))
        self.assertEqual(hub.parse_sources("all"),("files","shelf","memory"))
        self.assertEqual(hub.parse_sources("files, files,voice"),("files","voice"))
        for bad in ("memory,voice","clipboard","", "all,clipboard"):
            with self.assertRaises(ValueError):
                hub.parse_sources(bad)

    def test_query_and_limit_budgets(self):
        hub.validate_query("short","10" if False else 10)
        for text in ("", "\x00", "ñ"*400):
            with self.assertRaises(ValueError):
                hub.validate_query(text,8)
        with self.assertRaises(ValueError):
            hub.validate_query("x",21)

    def test_commands_route_to_existing_authorities(self):
        files=hub.command_for("files","scene",8,self.paths)
        self.assertEqual(files[0][2],"search")
        self.assertIn("scene",files[0])
        shelf=hub.command_for("shelf","board",8,self.paths)
        self.assertEqual(shelf[0][2:4],["shelf","search"])
        voice=hub.command_for("voice","teacher",8,self.paths)
        self.assertIn("--no-store",voice[0])
        self.assertIn("source:voicearchive teacher",voice[0])
        self.assertNotIn("--related-meaning",voice[0])
        self.assertEqual(voice[1],self.memory)

    def test_malicious_runtime_ref_is_not_executed(self):
        self.receipt.write_text(json.dumps({"schema":"memorycore_host_runtime_ref_v1",
                                           "python":str(self.paths.searchctl),
                                           "python_sha256":hashlib.sha256(b"").hexdigest()}))
        self.assertIsNone(hub.memory_python(self.paths))
        self.assertIsNone(hub.command_for("memory","x",3,self.paths))

    def test_modified_memorycore_interpreter_is_rejected(self):
        assert hub.memory_python(self.paths) is not None
        (self.runtime / "runtimes" / "python.exe").write_bytes(b"modified interpreter")
        self.assertIsNone(hub.memory_python(self.paths))
        self.assertIsNone(hub.command_for("voice","test",3,self.paths))

    def test_owner_failures_do_not_leak_private_stderr(self):
        def failure(args,cwd,timeout):
            return 1,b"",b"secret original clipboard title, private notes"
        output=hub.query_owner("shelf","special",3,self.paths,failure)
        self.assertEqual(output["status"],"unavailable")
        self.assertNotIn("secret",json.dumps(output))
        def malformed(args,cwd,timeout):
            return 0,b"not json",b""
        self.assertEqual(hub.query_owner("files","x",2,self.paths,malformed)["status"],"error")
        def oversize(args,cwd,timeout):
            return 0,b"x"*(hub.MAX_CAPTURE+1),b""
        self.assertEqual(hub.query_owner("files","x",2,self.paths,oversize)["status"],"error")

    def test_memory_timeout_is_classified(self):
        def timeout(*args):
            raise subprocess.TimeoutExpired(cmd="private", timeout=1.0)
        output=hub.query_owner("memory","private",3,self.paths,timeout)
        self.assertEqual(output["reason"],"owner_deadline_exceeded")
        self.assertNotIn("private",json.dumps(output))

    def test_fast_results_not_blocked_by_slow_memory(self):
        def fake(args,cwd,timeout):
            if args[2:4]==["shelf","search"]:
                time.sleep(0.009)
                return 0,json.dumps({"ok":True,"data":{"results":[{"id":"test"}]}}).encode(),b""
            if "memorycore" in args:
                time.sleep(0.1)
                return 0,json.dumps({"ok":True,"results":[]}).encode(),b""
            time.sleep(0.025)
            return 0,json.dumps({"ok":True,"data":{"hits":[]}}).encode(),b""
        start=time.perf_counter()
        stream=hub.iter_results("synthetic",("files","shelf","memory"),5,self.paths,fake)
        first=next(stream)
        elapsed=(time.perf_counter()-start)*1000
        self.assertEqual(first["source"],"shelf")
        self.assertLess(elapsed,65)
        rest=list(stream)
        self.assertEqual(set(x["source"] for x in rest),{"files","memory"})
        self.assertEqual(first["rows"],1)

    def test_no_unconfigured_file_service_is_fabricated(self):
        self.paths.searchctl.unlink()
        result=hub.query_owner("files","video",4,self.paths)
        self.assertEqual(result["reason"],"owner_install_unavailable")
        self.assertNotIn("owner_response",result)

    def test_stopped_file_agent_returns_without_spawning_a_cli(self):
        missing = Path(self.tmp.name) / "search" / "ipc-endpoint.json"
        paths=hub.Paths(self.paths.searchctl,self.paths.memory_root,
                        self.paths.memory_receipt,missing)
        seen=[]
        def should_not_launch(*args):
            seen.append(args)
            raise AssertionError("Stopped agent must not trigger CLI launch")
        result=hub.query_owner("files","clip",5,paths,should_not_launch)
        self.assertEqual(result["reason"],"agent_not_running")
        self.assertEqual(seen,[])
        shelf=hub.query_owner("shelf","clip",5,paths,
                  lambda *_: (0,json.dumps({"ok":True,"data":{"results":[]}}).encode(),b""))
        self.assertEqual(shelf["status"],"ready")

    def test_existing_private_file_agent_endpoint_allows_real_owner(self):
        endpoint=Path(self.tmp.name)/"ipc-endpoint.json"
        endpoint.write_text("synthetic testing only")
        paths=hub.Paths(self.paths.searchctl,self.paths.memory_root,self.paths.memory_receipt,endpoint)
        result=hub.query_owner("files","scene",5,paths,
                 lambda *_: (0,json.dumps({"ok":True,"data":{"hits":[{"id":"1"}]}}).encode(),b""))
        self.assertEqual(result["status"],"ready")
        self.assertEqual(result["rows"],1)


if __name__=="__main__":
    unittest.main()

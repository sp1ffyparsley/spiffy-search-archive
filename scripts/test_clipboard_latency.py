"""No-user-data parser and percentile tests for the Shelf timing audit."""
from __future__ import annotations
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

PATH=Path(__file__).with_name("diagnose_clipboard_latency.py")
SPEC=importlib.util.spec_from_file_location("diagnose_clipboard_latency", PATH)
module=importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name]=module
SPEC.loader.exec_module(module)

class ClipboardLatencyTests(unittest.TestCase):
    def test_known_content_free_timing_line(self):
        raw='2026-11-14 INFO Clipboard interaction stage timing; acquire/dispatch are IPC scheduling stages, render/ack are renderer frame boundaries; no content logged phase=PresentationRender elapsed_ms=263'
        self.assertEqual(module.extract(raw),("phase.PresentationRender",263))
    def test_ipc_and_worker(self):
        self.assertEqual(module.extract('Clipboard IPC phase timing; no content logged operation="search" discovery_ms=0 ipc_ms=165 total_ms=165 transport_ok=true'),("ipc.search",165))
        self.assertEqual(module.extract('Clipboard search completed without retaining the copy authorization lock operation="search" worker_queue_ms=1 lock_wait_ms=0 total_ms=171'),("worker.search",171))
        self.assertEqual(module.extract_diagnostics('Clipboard search completed without retaining the copy authorization lock operation="search" worker_queue_ms=1 lock_wait_ms=0 total_ms=171'),[("worker_queue.search",1),("worker_lock_wait.search",0)])
        self.assertEqual(module.extract_diagnostics('Clipboard IPC phase timing; no content logged operation="search" discovery_ms=0 ipc_ms=165 total_ms=165 transport_ok=true'),[("ipc_transport.search",165)])
    def test_private_query_is_never_parsed(self):
        self.assertIsNone(module.extract("Search query=personal note title SECRET"))
        self.assertEqual(module.percentile([],0.95),None)
        self.assertEqual(module.percentile([5,15,40],0.95),40)
    def test_report_has_no_private_text(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t)
            (root/"spiffy-shelf.log.2026-11-14").write_text(
                'Clipboard interaction stage timing; no content logged phase=PresentationRender elapsed_ms=80 private=SECRET\n'
                'Clipboard interaction stage timing; no content logged phase=PresentationRender elapsed_ms=150\n'
                'not-clipboard private=SECRET\n',encoding="utf-8")
            result=module.review(root)
            import json
            self.assertNotIn("SECRET",json.dumps(result))
            self.assertEqual(result["aggregate"]["phase.PresentationRender"]["p95_ms"],150)
if __name__=="__main__":unittest.main()

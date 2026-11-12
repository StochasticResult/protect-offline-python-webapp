"""Baseline unit & HTTP integration tests for the Mini Calc offline fixture."""

from __future__ import annotations

import json
import math
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from app_server import create_server
from core import spectrum_core
from core.spectrum_core import SpectrumInputError


class MiniCalcBehaviorTests(unittest.TestCase):
    def test_normal_sine_and_harmonic_calculation(self) -> None:
        samples = [
            math.sin(2.0 * math.pi * i / 8.0) + 0.1 * math.sin(4.0 * math.pi * i / 8.0)
            for i in range(16)
        ]
        res = spectrum_core.analyze_harmonics(samples, sample_rate_hz=1600.0, mode="standard")
        self.assertEqual(res["sample_count"], 16)
        self.assertAlmostEqual(res["fundamental_hz"], 200.0, places=6)
        self.assertAlmostEqual(res["thd_percent"], 10.0, places=4)
        self.assertGreater(res["calibrated_rms"], 0.7)

    def test_boundary_zero_signal_and_minimum_length(self) -> None:
        zero_res = spectrum_core.analyze_harmonics([0.0, 0.0, 0.0, 0.0], sample_rate_hz=100.0, mode="precision")
        self.assertEqual(zero_res["raw_rms"], 0.0)
        self.assertEqual(zero_res["calibrated_rms"], 0.0)
        self.assertEqual(zero_res["fundamental_bin"], 0)
        self.assertEqual(zero_res["thd_percent"], 0.0)

    def test_invalid_inputs_raise_structured_errors(self) -> None:
        with self.assertRaises(SpectrumInputError):
            spectrum_core.analyze_harmonics([1.0, 2.0, 3.0], sample_rate_hz=100.0)
        with self.assertRaises(SpectrumInputError):
            spectrum_core.analyze_harmonics([1.0, 0.0, -1.0, 0.0], sample_rate_hz=-50.0)
        with self.assertRaises(SpectrumInputError):
            spectrum_core.analyze_harmonics([1.0, float("nan"), -1.0, 0.0], sample_rate_hz=100.0)
        with self.assertRaises(SpectrumInputError):
            spectrum_core.analyze_harmonics([1.0, 0.0, -1.0, 0.0], sample_rate_hz=100.0, mode="unknown")

    def test_http_endpoints_and_data_dir_export(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_data:
            prev_data = os.environ.get("APP_DATA_DIR")
            os.environ["APP_DATA_DIR"] = tmp_data
            server = create_server("127.0.0.1", 0)
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
            thread.start()
            try:
                host, port = server.server_address[:2]
                base_url = f"http://{host}:{port}"

                with urllib.request.urlopen(f"{base_url}/", timeout=5) as resp:
                    html = resp.read().decode("utf-8")
                    self.assertEqual(resp.status, 200)
                    self.assertIn("Mini Calc Offline Harmonic Analyzer", html)

                req = urllib.request.Request(
                    f"{base_url}/api/jobs/import-export",
                    data=json.dumps(
                        {
                            "job_name": "unit_batch",
                            "records": [{"label": "a", "samples": [0.0, 1.0, 0.0, -1.0], "sample_rate_hz": 400.0}],
                        }
                    ).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    body = json.loads(resp.read().decode("utf-8"))
                    self.assertTrue(body["ok"])
                    self.assertTrue((Path(tmp_data) / "exports" / body["export_file"]).is_file())

                bad_req = urllib.request.Request(
                    f"{base_url}/api/analyze",
                    data=json.dumps({"samples": [1.0], "sample_rate_hz": 400.0}).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    urllib.request.urlopen(bad_req, timeout=5)
                self.assertEqual(ctx.exception.code, 400)
                ctx.exception.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)
                if prev_data is None:
                    os.environ.pop("APP_DATA_DIR", None)
                else:
                    os.environ["APP_DATA_DIR"] = prev_data


if __name__ == "__main__":
    unittest.main()

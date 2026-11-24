import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import Mock, patch

import httpx

from captive_tracer.app import NetworkIdentity, compare, main, network_identity, trace


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"done"
        status = 200
        headers = {"Content-Type": "text/plain"}
        if self.path == "/start":
            status = 302
            headers.update({"Location": "/cookie", "Set-Cookie": "session=yes; Path=/"})
        elif self.path == "/cookie":
            if self.headers.get("Cookie") != "session=yes":
                status = 403
            else:
                headers["Content-Type"] = "text/html"
                body = b'<meta http-equiv="refresh" content="0; URL=\'/final?x=1&amp;y=2\'">'
        elif self.path == "/loop":
            status = 302
            headers["Location"] = "/loop#fragment"
        elif self.path == "/cookie-loop":
            if self.headers.get("Cookie") != "session=yes":
                status = 302
                headers.update({"Location": "/cookie-loop", "Set-Cookie": "session=yes; Path=/"})
        elif self.path == "/agent":
            body = self.headers.get("User-Agent", "").encode()
        elif self.path == "/large":
            body = b"x" * 100_000
        elif self.path == "/missing-location":
            status = 302
        elif self.path == "/bad-scheme":
            status = 302
            headers["Location"] = "file:///etc/passwd"
        elif self.path == "/cookie-state":
            body = self.headers.get("Cookie", "empty").encode()
        elif self.path == "/error":
            status = 503
        elif self.path == "/scripts":
            headers["Content-Type"] = "text/html"
            body = (
                b'<script src="/portal.js?x=1&amp;y=2"></script>'
                b'<script type="module">window.location = "/login";</script>'
                b'<script>unfinished()'
            )
        elif self.path == "/script-downloads":
            headers.update({"Content-Type": "text/html", "Set-Cookie": "script=yes; Path=/"})
            body = (
                b'<base href="/assets/"><script src="portal.js?x=1&amp;y=2"></script>'
                b'<script src="portal.js?x=1&amp;y=2"></script>'
                b'<script src="/redirect-script"></script><script>inline()</script>'
            )
        elif self.path == "/assets/portal.js?x=1&y=2":
            headers["Content-Type"] = "application/javascript"
            body = b"window.portal = true;"
            if self.headers.get("Cookie") != "script=yes":
                status = 403
        elif self.path == "/redirect-script":
            status = 302
            headers["Location"] = "/assets/portal.js?x=1&y=2"
        elif self.path == "/script-errors":
            headers["Content-Type"] = "text/html"
            body = (
                b'<script src="/large"></script><script src="/error"></script>'
                b'<script src="/bad-scheme"></script><script src="/loop"></script>'
                b'<script src="file:///not-a-script"></script>'
            )
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


class TraceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def run_trace(self, path, **kwargs):
        return trace(self.base + path, "test", "TestAgent/1", **kwargs)

    def test_http_meta_redirects_preserve_cookies_and_resolve_entities(self):
        result = self.run_trace("/start")
        self.assertIsNone(result.error)
        self.assertEqual([hop.status for hop in result.hops], [302, 200, 200])
        self.assertEqual(result.hops[0].redirect_type, "http")
        self.assertEqual(result.hops[1].redirect_type, "meta-refresh")
        self.assertEqual(result.hops[2].url, self.base + "/final?x=1&y=2")

    def test_meta_refresh_can_be_disabled(self):
        result = self.run_trace("/start", follow_meta=False)
        self.assertIsNone(result.error)
        self.assertEqual(len(result.hops), 2)
        self.assertIsNone(result.hops[-1].redirect_to)

    def test_loops_and_redirect_limit(self):
        result = self.run_trace("/loop")
        self.assertIn("loop", result.error)
        self.assertEqual(len(result.hops), 1)
        limited = self.run_trace("/start", max_redirects=0)
        self.assertIn("limit", limited.error)
        self.assertEqual(len(limited.hops), 1)
        cookie_loop = self.run_trace("/cookie-loop")
        self.assertIsNone(cookie_loop.error)
        self.assertEqual(len(cookie_loop.hops), 2)

    def test_body_sample_is_bounded(self):
        result = self.run_trace("/large", max_body_bytes=17)
        self.assertIsNone(result.error)
        self.assertEqual(result.hops[0].sampled_bytes, 17)
        self.assertTrue(result.hops[0].body_truncated)
        exact = self.run_trace("/final", max_body_bytes=4)
        self.assertFalse(exact.hops[0].body_truncated)

    def test_comparison_detects_agent_behavior_but_ignores_timing(self):
        first = trace(self.base + "/agent", "a", "Agent-A")
        second = trace(self.base + "/agent", "b", "Agent-B")
        same = trace(self.base + "/agent", "c", "Agent-A")
        same.hops[0].elapsed_ms = first.hops[0].elapsed_ms + 100
        self.assertEqual(compare([first, second, same])["different_profiles"], ["b"])

    def test_cookie_jars_are_isolated(self):
        self.run_trace("/start")
        fresh = self.run_trace("/cookie")
        self.assertEqual(fresh.hops[0].status, 403)

    def test_invalid_redirects_are_reported_with_the_hop(self):
        for path in ("/missing-location", "/bad-scheme"):
            with self.subTest(path=path):
                result = self.run_trace(path)
                self.assertIsNotNone(result.error)
                self.assertEqual(len(result.hops), 1)

    def test_json_cli_shape_and_exit_codes(self):
        with tempfile.TemporaryDirectory() as temporary, contextlib.redirect_stderr(io.StringIO()):
            root = Path(temporary)
            for platform in ("iphone", "windows"):
                output = io.StringIO()
                args = [
                    self.base + "/agent", "--platform", platform,
                    "--output", str(root / platform), "--json",
                ]
                if platform == "windows":
                    args.extend(["--compare-with", str(root / "iphone")])
                with contextlib.redirect_stdout(output):
                    code = main(args)
                report = json.loads(output.getvalue())
                self.assertEqual(code, 0)
                self.assertEqual(report["status"], "completed")
                self.assertEqual(len(report["traces"]), 1)
                self.assertEqual(report["traces"][0]["profile"], platform)
            self.assertEqual(report["comparison"]["baseline"], "iphone")
            self.assertEqual(report["comparison"]["different_profiles"], ["windows"])
            with contextlib.redirect_stdout(io.StringIO()):
                for path, code in (("/loop", 1), ("/error", 0)):
                    self.assertEqual(main([
                        self.base + path, "--platform", "curl",
                        "--output", str(root / path.removeprefix("/")),
                    ]), code)

    def test_invalid_cli_arguments(self):
        for args in (
            ["file:///tmp/test", "--platform", "iphone"],
            [self.base, "--platform", "windows", "--timeout", "nan"],
            [self.base, "--platform", "windows", "--max-body-bytes", "0"],
            [self.base, "--platform", "windows", "--max-redirects", "-1"],
            [self.base],
            ["--platform", "curl"],
        ):
            with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as exc:
                    main(args)
                self.assertEqual(exc.exception.code, 2)

    def test_platform_defaults_and_explicit_url_override(self):
        expected_urls = {
            "iphone": "http://captive.apple.com/hotspot-detect.html",
            "windows": "http://www.msftconnecttest.com/connecttest.txt",
            "android": "http://connectivitycheck.gstatic.com/generate_204",
            "apple-captive": "http://captive.apple.com/hotspot-detect.html",
        }
        with tempfile.TemporaryDirectory() as temporary, contextlib.redirect_stdout(
            io.StringIO()
        ), contextlib.redirect_stderr(io.StringIO()):
            for platform, expected in expected_urls.items():
                with self.subTest(platform=platform), patch(
                    "captive_tracer.app.httpx.Client.send",
                    side_effect=httpx.ConnectError("test: no external requests"),
                ) as send:
                    output = Path(temporary) / platform
                    self.assertEqual(main([
                        "--platform", platform, "--output", str(output),
                    ]), 1)
                    self.assertEqual(str(send.call_args.args[0].url), expected)
                    report = json.loads((output / "report.json").read_text())
                    self.assertEqual(report["url"], expected)
                    self.assertEqual(report["settings"]["url_source"], "platform-default")
            output = Path(temporary) / "override"
            self.assertEqual(main([
                self.base + "/final", "--platform", "iphone", "--output", str(output),
            ]), 0)
            report = json.loads((output / "report.json").read_text())
            self.assertEqual(report["url"], self.base + "/final")
            self.assertEqual(report["settings"]["url_source"], "explicit")

    def test_comparison_allows_different_probe_urls_and_explains_difference(self):
        with tempfile.TemporaryDirectory() as temporary, contextlib.redirect_stdout(
            io.StringIO()
        ), contextlib.redirect_stderr(io.StringIO()):
            root = Path(temporary)
            self.assertEqual(main([
                self.base + "/final", "--platform", "iphone",
                "--output", str(root / "iphone"),
            ]), 0)
            self.assertEqual(main([
                self.base + "/agent", "--platform", "windows",
                "--output", str(root / "windows"), "--compare-with", str(root / "iphone"),
            ]), 0)
            report = json.loads((root / "windows" / "report.json").read_text())
            self.assertFalse(report["comparison"]["starting_urls_match"])
            self.assertEqual(report["comparison"]["baseline_url"], self.base + "/final")
            self.assertIn("Starting URLs differ", (root / "windows" / "summary.txt").read_text())

    def test_capture_is_persistent_and_records_headers_bodies_and_scripts(self):
        with tempfile.TemporaryDirectory() as temporary, contextlib.redirect_stdout(
            io.StringIO()
        ), contextlib.redirect_stderr(io.StringIO()):
            output = Path(temporary) / "capture"
            self.assertEqual(main([
                self.base + "/scripts", "--platform", "iphone", "--output", str(output),
            ]), 0)
            report = json.loads((output / "report.json").read_text())
            hop = report["traces"][0]["hops"][0]
            body = (output / hop["body_file"]).read_bytes()
            self.assertIn(b"unfinished()", body)
            self.assertEqual(len(hop["scripts"]), 3)
            self.assertTrue(hop["request_headers"])
            self.assertIn(["content-type", "text/html"], hop["response_headers"])
            self.assertIn("SCRIPT", (output / "summary.txt").read_text())
            self.assertTrue((output / "iphone" / "trace.json").is_file())
            self.assertTrue((output / "iphone" / "request-000.json").is_file())
            self.assertTrue((output / "iphone" / "hop-000.json").is_file())
            self.assertIsNotNone(report["finished_at"])

    def test_connection_errors_and_interruptions_still_persist(self):
        with tempfile.TemporaryDirectory() as temporary, contextlib.redirect_stdout(
            io.StringIO()
        ), contextlib.redirect_stderr(io.StringIO()):
            for name, error, code in (
                ("offline", httpx.ConnectError("offline"), 1),
                ("interrupt", KeyboardInterrupt(), 130),
            ):
                output = Path(temporary) / name
                with patch("captive_tracer.app.httpx.Client.send", side_effect=error):
                    self.assertEqual(main([
                        self.base, "--platform", "windows", "--output", str(output),
                    ]), code)
                report = json.loads((output / "report.json").read_text())
                self.assertIn(report["status"], ("failed", "interrupted"))
                self.assertIsNotNone(report["traces"][0]["error"])
                self.assertTrue((output / "windows" / "request-000.json").exists())
                self.assertIsNotNone(json.loads(
                    (output / "windows" / "trace.json").read_text()
                )["finished_at"])

    def test_existing_capture_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary, contextlib.redirect_stderr(io.StringIO()):
            marker = Path(temporary) / "existing"
            marker.write_text("keep")
            with self.assertRaises(SystemExit) as exc:
                main([self.base, "--platform", "iphone", "--output", temporary])
            self.assertEqual(exc.exception.code, 2)
            self.assertEqual(marker.read_text(), "keep")

    def test_standalone_process_needs_no_agent(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "capture"
            completed = subprocess.run(
                [
                    sys.executable, "-m", "captive_tracer", self.base + "/start",
                    "--platform", "windows", "--output", str(output), "--json",
                ],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            report = json.loads(completed.stdout)
            self.assertEqual(len(report["traces"]), 1)
            self.assertEqual(len(report["traces"][0]["hops"]), 3)
            self.assertEqual(json.loads((output / "report.json").read_text()), report)

    @unittest.skipUnless(sys.platform == "win32" and shutil.which("uv"), "requires Windows and uv")
    def test_windows_launcher_captures_scripts_from_another_working_directory(self):
        launcher = Path(__file__).resolve().parents[1] / "captive-tracer.cmd"
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "capture with spaces"
            completed = subprocess.run(
                [
                    os.environ["COMSPEC"], "/d", "/c", str(launcher),
                    self.base + "/script-downloads", "--platform", "curl",
                    "--output", str(output), "--json",
                ],
                cwd=temporary, capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            report = json.loads(completed.stdout)
            self.assertEqual(report["platform"], "curl")
            downloads = report["traces"][0]["script_downloads"]
            self.assertEqual(len(downloads), 2)
            self.assertEqual(
                (output / downloads[0]["body_file"]).read_bytes(), b"window.portal = true;",
            )

    def test_scripts_are_noted_without_execution_even_when_meta_disabled(self):
        result = self.run_trace("/scripts", follow_meta=False)
        self.assertIsNone(result.error)
        self.assertEqual(len(result.hops), 1)
        scripts = result.hops[0].scripts
        self.assertEqual(len(scripts), 3)
        self.assertEqual(scripts[0].source_url, self.base + "/portal.js?x=1&y=2")
        self.assertEqual(scripts[1].script_type, "module")
        self.assertIn('window.location = "/login";', scripts[1].inline_preview)
        self.assertIsNotNone(scripts[1].inline_sha256)
        self.assertEqual(scripts[2].inline_preview, "unfinished()")

    def test_external_scripts_are_saved_with_urls_metadata_and_session_cookies(self):
        with tempfile.TemporaryDirectory() as temporary, contextlib.redirect_stdout(
            io.StringIO()
        ), contextlib.redirect_stderr(io.StringIO()):
            output = Path(temporary) / "capture"
            self.assertEqual(main([
                self.base + "/script-downloads", "--platform", "windows",
                "--output", str(output),
            ]), 0)
            directory = output / "windows" / "scripts"
            urls = (directory / "urls.txt").read_text().splitlines()
            self.assertEqual(urls, [
                self.base + "/assets/portal.js?x=1&y=2",
                self.base + "/redirect-script",
            ])
            manifest = json.loads((directory / "manifest.json").read_text())
            self.assertEqual(len(manifest), 2)
            for item in manifest:
                self.assertIsNone(item["error"])
                self.assertEqual(item["status"], 200)
                self.assertEqual(item["final_url"], urls[0])
                self.assertEqual((output / item["body_file"]).read_bytes(), b"window.portal = true;")
                self.assertFalse(item["body_truncated"])
            report = json.loads((output / "report.json").read_text())
            self.assertEqual(report["traces"][0]["script_downloads"], manifest)
            self.assertEqual(len(report["traces"][0]["hops"]), 1)
            self.assertIn("SCRIPT DOWNLOAD", (output / "summary.txt").read_text())
            self.assertEqual(main([
                self.base + "/final", "--platform", "windows",
                "--output", str(Path(temporary) / "comparison"),
                "--compare-with", str(output),
            ]), 0)

    def test_script_downloads_are_bounded_and_failures_are_explicit(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "windows"
            result = trace(
                self.base + "/script-errors", "windows", "TestAgent/1",
                output_dir=output, max_body_bytes=512, max_redirects=1,
            )
            self.assertIsNone(result.error)
            large, failed, invalid_redirect, loop, invalid_url = result.script_downloads
            self.assertEqual(large.sampled_bytes, 512)
            self.assertTrue(large.body_truncated)
            self.assertEqual((output / "scripts" / "script-000.js").stat().st_size, 512)
            self.assertEqual(failed.error, "HTTP 503")
            self.assertIn("HTTP(S)", invalid_redirect.error)
            self.assertIn("limit", loop.error)
            self.assertIn("HTTP(S)", invalid_url.error)
            self.assertIsNone(invalid_url.body_file)
            self.assertEqual(len(json.loads(
                (output / "scripts" / "manifest.json").read_text()
            )), 5)

    def test_mac_inspection_matches_the_actual_connection(self):
        response = Mock()
        response.extensions = {"network_stream": Mock()}
        response.extensions["network_stream"].get_extra_info.return_value.getsockname.return_value = (
            "192.0.2.10", 12345,
        )
        interfaces = [
            {"ifname": "other", "link_type": "ether", "address": "00:11:22:33:44:55",
             "addr_info": [{"local": "192.0.2.9"}]},
            {"ifname": "wlan0", "link_type": "ether", "address": "AA:BB:CC:DD:EE:FF",
             "addr_info": [{"local": "192.0.2.10"}]},
        ]
        with patch("captive_tracer.app.sys.platform", "linux"), patch(
            "captive_tracer.app.subprocess.run",
            return_value=Mock(stdout=json.dumps(interfaces)),
        ):
            identity = network_identity(response)
        self.assertIsNone(identity.error)
        self.assertEqual(identity.interface, "wlan0")
        self.assertEqual(identity.mac, "aa:bb:cc:dd:ee:ff")

    def test_mac_inspection_failure_is_explicit(self):
        response = Mock()
        response.extensions = {}
        identity = network_identity(response)
        self.assertIsNone(identity.mac)
        self.assertIn("socket", identity.error)

    def test_mac_rotation_is_separate_from_behavior_comparison(self):
        first = self.run_trace("/final")
        second = self.run_trace("/final")
        first.network = NetworkIdentity(mac="00:11:22:33:44:55")
        second.network = NetworkIdentity(mac="00:11:22:33:44:66")
        self.assertEqual(compare([first, second])["mac_rotation"][0]["status"], "changed")
        self.assertEqual(compare([first, second])["different_profiles"], [])
        second.network.mac = first.network.mac
        self.assertEqual(compare([first, second])["mac_rotation"][0]["status"], "unchanged")
        second.network.mac = None
        self.assertEqual(compare([first, second])["mac_rotation"][0]["status"], "unknown")


if __name__ == "__main__":
    unittest.main()

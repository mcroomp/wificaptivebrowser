import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs

from playwright.sync_api import BrowserContext, Error as PlaywrightError

from captive_tracer.app import main
from captive_tracer.browser import IDENTIFICATION, run_browser


class BrowserTests(unittest.TestCase):
    def setUp(self):
        manager = patch("captive_tracer.browser.sync_playwright")
        self.addCleanup(manager.stop)
        self.playwright = manager.start().return_value.__enter__.return_value
        self.browser = MagicMock()
        self.playwright.chromium.launch.return_value = self.browser
        self.playwright.webkit.launch.return_value = self.browser
        self.playwright.devices = {"iPhone 13": {"user_agent": "iPhone preset", "is_mobile": True}}
        self.context = self.browser.new_context.return_value
        self.page = self.context.new_page.return_value
        self.page.evaluate.return_value = {"userAgent": "actual browser", "platform": "Win32"}
        self.output = io.StringIO()
        for target in ("stdout", "stderr"):
            redirect = getattr(contextlib, f"redirect_{target}")(self.output)
            redirect.__enter__()
            self.addCleanup(redirect.__exit__, None, None, None)

    def test_browser_monitoring_is_off_by_default(self):
        with patch("builtins.input", return_value=""), patch(
            "captive_tracer.browser.save_json"
        ) as save:
            self.assertEqual(main(["--browser", "--platform", "windows"]), 0)
        self.playwright.chromium.launch.assert_called_once_with(channel="msedge", headless=False)
        self.assertNotIn("user_agent", self.browser.new_context.call_args.kwargs)
        self.assertIsNone(self.browser.new_context.call_args.kwargs["record_har_path"])
        save.assert_not_called()
        self.context.close.assert_called_once()
        self.browser.close.assert_called_once()

    def test_monitoring_records_actual_identity_and_json_stdout(self):
        with tempfile.TemporaryDirectory() as temporary, patch(
            "builtins.input", return_value="",
        ), contextlib.redirect_stdout(io.StringIO()) as stdout:
            output = Path(temporary) / "capture"
            self.assertEqual(main([
                "--browser", "--platform", "iphone", "--monitor",
                "--output", str(output), "--json",
            ]), 0)
            report = json.loads(stdout.getvalue())
            self.assertEqual(report, json.loads((output / "report.json").read_text()))
            self.assertEqual(report["identification"], self.page.evaluate.return_value)
            self.assertEqual(report["status"], "completed")
            options = self.browser.new_context.call_args.kwargs
            self.assertEqual(options["user_agent"], "iPhone preset")
            self.assertTrue(options["is_mobile"])
            self.assertEqual(options["record_har_path"], output / "network.har")
            self.assertEqual(options["record_har_content"], "embed")
        self.playwright.webkit.launch.assert_called_once_with(headless=False)

    def test_initial_navigation_failure_allows_manual_retry(self):
        self.page.goto.side_effect = PlaywrightError("navigation timeout")
        with tempfile.TemporaryDirectory() as temporary, patch(
            "builtins.input", return_value="",
        ) as wait:
            output = Path(temporary)
            self.assertEqual(run_browser("http://example.test", "windows", output_dir=output), 0)
            report = json.loads((output / "report.json").read_text())
            self.assertIn("navigation timeout", report["navigation_error"])
            wait.assert_called_once()
        self.assertIn("retry", self.output.getvalue())

    def test_startup_error_and_interruption_are_reported(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            self.playwright.webkit.launch.side_effect = PlaywrightError("missing engine")
            self.assertEqual(run_browser("http://example.test", "iphone", output_dir=output), 1)
            report = json.loads((output / "report.json").read_text())
            self.assertEqual(report["status"], "failed")
            self.assertIn("missing engine", report["error"])
            with patch("builtins.input", side_effect=KeyboardInterrupt):
                self.assertEqual(run_browser("http://example.test", "windows", output_dir=output), 130)
            report = json.loads((output / "report.json").read_text())
            self.assertEqual(report["status"], "interrupted")
            self.assertIsNotNone(report["finished_at"])
        self.context.close.assert_called_once()

    def test_invalid_browser_options_are_rejected_before_launch(self):
        for args in (
            ["--monitor", "--platform", "windows"],
            ["--browser", "--platform", "android"],
            ["--browser", "--platform", "windows", "--output", "unused"],
            ["--browser", "--platform", "windows", "--json"],
            ["--browser", "--platform", "windows", "--max-body-bytes", "10"],
            ["--browser", "--platform", "windows", "--max-redirects", "10"],
            ["--browser", "--platform", "windows", "--no-meta-refresh"],
            ["--browser", "--platform", "windows", "--compare-with", "unused"],
        ):
            with self.subTest(args=args), self.assertRaises(SystemExit) as exc:
                main(args)
            self.assertEqual(exc.exception.code, 2)
        self.playwright.chromium.launch.assert_not_called()
        self.playwright.webkit.launch.assert_not_called()


class LoginHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        status = 200
        headers = {"Content-Type": "text/html"}
        if self.path == "/start":
            status = 302
            headers.update({"Location": "/login", "Set-Cookie": "session=local; Path=/"})
            body = b""
        elif self.path == "/form.js":
            headers["Content-Type"] = "application/javascript"
            body = (
                b'window.browserPlatform = navigator.platform;'
                b'document.addEventListener("DOMContentLoaded", () => {'
                b'const token = document.createElement("input");'
                b'token.type = "hidden"; token.name = "_csrf"; token.value = "local-token";'
                b'document.querySelector("form").appendChild(token); });'
            )
        elif self.path == "/login":
            body = (
                b'<html><head><script src="/form.js"></script></head><body>'
                b'<form action="/done" method="post"><input name="name">'
                b'<button type="submit">Continue</button></form></body></html>'
            )
        else:
            status = 404
            body = b"not found"
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        form = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
        valid = (
            self.path == "/done" and form == {"name": ["test"], "_csrf": ["local-token"]}
            and self.headers.get("Cookie") == "session=local"
        )
        body = b"<h1>Logged in</h1>" if valid else b"<h1>Invalid session or form</h1>"
        self.send_response(200 if valid else 403)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


@unittest.skipUnless(
    os.environ.get("CAPTIVE_BROWSER_TESTS") == "1",
    "set CAPTIVE_BROWSER_TESTS=1 with Edge and Playwright WebKit installed",
)
class BrowserIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), LoginHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def test_interactive_login_identity_and_optional_har_for_both_platforms(self):
        original_new_page = BrowserContext.new_page
        for platform in ("windows", "iphone"):
            for monitor in (False, True):
                with self.subTest(platform=platform, monitor=monitor), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    pages = []

                    def new_page(context):
                        page = original_new_page(context)
                        pages.append(page)
                        return page

                    def complete_login():
                        page = pages[0]
                        identity = page.evaluate(IDENTIFICATION)
                        self.assertEqual(page.evaluate("window.browserPlatform"), identity["platform"])
                        if platform == "iphone":
                            self.assertIn("iPhone", identity["userAgent"])
                            self.assertEqual(identity["platform"], "iPhone")
                            self.assertGreater(identity["maxTouchPoints"], 0)
                        else:
                            self.assertIn("Windows", identity["userAgent"])
                            self.assertIn("Edg/", identity["userAgent"])
                            self.assertEqual(identity["platform"], "Win32")
                        page.locator('input[name="name"]').fill("test")
                        page.get_by_role("button", name="Continue").click()
                        page.wait_for_url(self.base + "/done")
                        self.assertEqual(page.locator("h1").inner_text(), "Logged in")
                        return ""

                    with patch.object(
                        BrowserContext, "new_page", autospec=True, side_effect=new_page,
                    ), patch("builtins.input", side_effect=complete_login), contextlib.redirect_stderr(io.StringIO()):
                        self.assertEqual(run_browser(
                            self.base + "/start", platform,
                            output_dir=root if monitor else None, timeout=20,
                        ), 0)
                    if monitor:
                        report = json.loads((root / "report.json").read_text())
                        self.assertEqual(report["status"], "completed")
                        har = json.loads((root / "network.har").read_text(encoding="utf-8"))
                        entries = har["log"]["entries"]
                        self.assertTrue(any(
                            entry["request"]["url"].endswith("/form.js")
                            and entry["response"]["content"].get("text")
                            for entry in entries
                        ))
                        self.assertTrue(any(
                            entry["request"]["method"] == "POST"
                            and "_csrf" in entry["request"]["postData"]["text"]
                            and entry["response"]["status"] == 200
                            for entry in entries
                        ))
                    else:
                        self.assertEqual(list(root.iterdir()), [])

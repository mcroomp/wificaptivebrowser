from __future__ import annotations

import json
from pathlib import Path
import sys

from playwright.sync_api import Error as PlaywrightError, sync_playwright

from .app import save_json, utc_now


IDENTIFICATION = """() => ({
    userAgent: navigator.userAgent,
    platform: navigator.platform,
    appCodeName: navigator.appCodeName,
    appVersion: navigator.appVersion,
    language: navigator.language,
    languages: Array.from(navigator.languages),
    maxTouchPoints: navigator.maxTouchPoints,
    screen: {
        width: screen.width, height: screen.height,
        availWidth: screen.availWidth, availHeight: screen.availHeight
    },
    viewport: {width: innerWidth, height: innerHeight}
})"""


def run_browser(
    url: str,
    platform: str,
    *,
    output_dir: Path | None = None,
    user_agent: str | None = None,
    timeout: float = 10,
    print_json: bool = False,
) -> int:
    report = {
        "schema_version": 1,
        "mode": "browser",
        "platform": platform,
        "url": url,
        "started_at": utc_now(),
        "finished_at": None,
        "status": "running",
        "error": None,
        "navigation_error": None,
        "identification": None,
        "har_file": "network.har" if output_dir is not None else None,
    }

    def persist() -> None:
        if output_dir is not None:
            save_json(output_dir / "report.json", report)

    code = 0
    try:
        persist()
        with sync_playwright() as playwright:
            browser = (
                playwright.webkit.launch(headless=False)
                if platform == "iphone"
                else playwright.chromium.launch(channel="msedge", headless=False)
            )
            try:
                options = dict(playwright.devices["iPhone 13"]) if platform == "iphone" else {}
                if user_agent is not None:
                    options["user_agent"] = user_agent
                context = browser.new_context(
                    **options,
                    record_har_path=output_dir / "network.har" if output_dir is not None else None,
                    record_har_content="embed" if output_dir is not None else None,
                    record_har_mode="full" if output_dir is not None else None,
                )
                try:
                    if platform == "iphone":
                        # WebKit on Windows does not emulate these navigator properties.
                        context.add_init_script("""Object.defineProperties(Navigator.prototype, {
                            platform: {get: () => "iPhone", configurable: true},
                            maxTouchPoints: {get: () => 5, configurable: true}
                        });""")
                    page = context.new_page()
                    report["identification"] = page.evaluate(IDENTIFICATION)
                    persist()
                    try:
                        page.goto(url, wait_until="load", timeout=timeout * 1000)
                    except PlaywrightError as exc:
                        report["navigation_error"] = str(exc)
                        persist()
                        print(
                            f"WARNING: Initial navigation failed: {exc}\n"
                            "You can retry or navigate manually in the browser.",
                            file=sys.stderr,
                        )
                    print(
                        f"Interactive {platform} browser opened. "
                        + (
                            f"Monitoring ON: saving sensitive network traffic to {output_dir}."
                            if output_dir is not None else "Monitoring OFF: no capture files are saved."
                        ),
                        file=sys.stderr, flush=True,
                    )
                    print(
                        "Complete login in the browser, then press Enter here "
                        "to close the session and finish: ",
                        file=sys.stderr, flush=True,
                    )
                    input()
                finally:
                    context.close()
            finally:
                browser.close()
        report["status"] = "completed"
    except KeyboardInterrupt:
        code = 130
        report["status"] = "interrupted"
        report["error"] = "Interrupted by user"
    except (PlaywrightError, EOFError) as exc:
        code = 1
        report["status"] = "failed"
        report["error"] = str(exc)
        print(
            f"ERROR: {exc}\n"
            "Browser setup: install Microsoft Edge for Windows mode; "
            "run 'uv run playwright install webkit' for iPhone mode. "
            "Keep this terminal open for interactive input.",
            file=sys.stderr,
        )
    except OSError as exc:
        print(f"ERROR: Could not persist browser capture: {exc}", file=sys.stderr)
        return 1
    report["finished_at"] = utc_now()
    try:
        persist()
    except OSError as exc:
        print(f"ERROR: Could not finalize browser capture: {exc}", file=sys.stderr)
        return 1
    if print_json:
        print(json.dumps(report, indent=2))
    return code

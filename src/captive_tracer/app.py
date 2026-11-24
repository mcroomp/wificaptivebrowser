from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import json
import math
import re
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx


PROFILES = {
    "windows": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 "
        "Safari/537.36 Edg/131.0.0.0"
    ),
    "chrome": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    ),
    "firefox": "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "iphone": (
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"
    ),
    "android": (
        "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36"
    ),
    "apple-captive": "CaptiveNetworkSupport-407.0.0.1.3 wispr",
    "curl": "curl/8.11.0",
}
DEFAULT_URLS = {
    "iphone": "http://captive.apple.com/hotspot-detect.html",
    "apple-captive": "http://captive.apple.com/hotspot-detect.html",
    "windows": "http://www.msftconnecttest.com/connecttest.txt",
    "android": "http://connectivitycheck.gstatic.com/generate_204",
}
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
REFRESH = re.compile(r"^\s*\d+(?:\.\d+)?\s*;\s*url\s*=\s*(.*?)\s*$", re.I)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def save_json(path: Path, data: object) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


@dataclass
class NetworkIdentity:
    local_ip: str | None = None
    interface: str | None = None
    mac: str | None = None
    error: str | None = None


@dataclass
class ScriptNote:
    source_url: str | None
    script_type: str
    inline_preview: str
    inline_sha256: str | None


@dataclass
class ScriptDownload:
    source_url: str
    final_url: str | None = None
    status: int | None = None
    body_file: str | None = None
    sampled_bytes: int = 0
    body_truncated: bool = True
    body_sha256: str | None = None
    error: str | None = None


@dataclass
class Hop:
    url: str
    status: int
    elapsed_ms: float
    content_type: str
    server: str
    sampled_bytes: int
    body_truncated: bool
    body_sha256: str
    redirect_type: str | None = None
    redirect_to: str | None = None
    scripts: list[ScriptNote] = field(default_factory=list)
    captured_at: str = field(default_factory=utc_now)
    request_headers: list[tuple[str, str]] = field(default_factory=list)
    response_headers: list[tuple[str, str]] = field(default_factory=list)
    body_file: str | None = None


@dataclass
class Trace:
    profile: str
    user_agent: str
    hops: list[Hop] = field(default_factory=list)
    error: str | None = None
    network: NetworkIdentity = field(default_factory=NetworkIdentity)
    started_at: str = field(default_factory=utc_now)
    finished_at: str | None = None
    interrupted: bool = False
    script_downloads: list[ScriptDownload] = field(default_factory=list)


class PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.target: str | None = None
        self.scripts: list[ScriptNote] = []
        self.base_url: str | None = None
        self._script_attrs: dict[str, str | None] | None = None
        self._script_body: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "base" and self.base_url is None:
            self.base_url = dict(attrs).get("href")
        if tag.lower() == "script":
            self._script_attrs = dict(attrs)
            self._script_body = []
            return
        if tag.lower() != "meta" or self.target is not None:
            return
        attributes = dict(attrs)
        if (attributes.get("http-equiv") or "").lower() != "refresh":
            return
        match = REFRESH.match(attributes.get("content") or "")
        if match:
            target = match.group(1)
            if len(target) >= 2 and target[0] == target[-1] and target[0] in "\"'":
                target = target[1:-1]
            if target:
                self.target = target

    def handle_data(self, data: str) -> None:
        if self._script_attrs is not None:
            self._script_body.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script":
            self.finish_script()

    def finish_script(self) -> None:
        if self._script_attrs is None:
            return
        body = "".join(self._script_body)
        self.scripts.append(ScriptNote(
            source_url=self._script_attrs.get("src"),
            script_type=self._script_attrs.get("type") or "text/javascript",
            inline_preview=body.strip()[:200],
            inline_sha256=hashlib.sha256(body.encode()).hexdigest() if body else None,
        ))
        self._script_attrs = None
        self._script_body = []

    def close(self) -> None:
        # Flush raw-text buffering when the sample ends inside a script.
        if self._script_attrs is not None:
            self.feed("</script>")
        super().close()


def network_identity(response: httpx.Response) -> NetworkIdentity:
    identity = NetworkIdentity()
    try:
        stream = response.extensions.get("network_stream")
        connection = stream.get_extra_info("socket") if stream is not None else None
        if connection is None:
            raise RuntimeError("The HTTP transport did not expose its connected socket")
        identity.local_ip = connection.getsockname()[0]
        if not sys.platform.startswith("linux"):
            raise RuntimeError("MAC inspection currently supports Linux with iproute2 only")
        completed = subprocess.run(
            ["ip", "-j", "address", "show"],
            check=True, capture_output=True, text=True, timeout=5,
        )
        for interface in json.loads(completed.stdout):
            if any(
                address.get("local") == identity.local_ip
                for address in interface.get("addr_info", [])
            ):
                identity.interface = interface["ifname"]
                mac = interface.get("address")
                if interface.get("link_type") != "ether" or not mac:
                    raise RuntimeError("Connected interface has no Ethernet/Wi-Fi MAC (loopback or tunnel)")
                identity.mac = mac.lower()
                return identity
        raise RuntimeError(f"No interface found for connected local IP {identity.local_ip}")
    except (
        OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError, RuntimeError,
    ) as exc:
        identity.error = f"{type(exc).__name__}: {exc}"
        return identity


def normalize_url(value: str) -> str:
    parts = urlsplit(value)
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        raise ValueError(f"Expected an absolute HTTP(S) URL, got {value!r}")
    if parts.username is not None or parts.password is not None:
        raise ValueError("Credentials in URLs are not supported")
    # Fragments are not sent to servers and must not hide redirect loops.
    return str(httpx.URL(urlunsplit(parts._replace(fragment=""))))


def capture_scripts(
    client: httpx.Client,
    result: Trace,
    output_dir: Path,
    max_redirects: int,
    max_body_bytes: int,
) -> None:
    urls = list(dict.fromkeys(
        script.source_url
        for hop in result.hops
        for script in hop.scripts
        if script.source_url is not None
    ))
    directory = output_dir / "scripts"
    directory.mkdir(mode=0o700)
    (directory / "urls.txt").write_text(
        "".join(url + "\n" for url in urls), encoding="utf-8",
    )
    manifest = directory / "manifest.json"
    save_json(manifest, [])
    for index, url in enumerate(urls):
        download = ScriptDownload(source_url=url)
        result.script_downloads.append(download)
        body = bytearray()
        try:
            current = normalize_url(url)
            for redirect in range(max_redirects + 1):
                download.final_url = current
                with client.stream("GET", current) as response:
                    download.status = response.status_code
                    if response.status_code in REDIRECT_STATUSES:
                        target = response.headers.get("location")
                        if target is None:
                            raise ValueError(f"HTTP {response.status_code} without a Location header")
                        if redirect == max_redirects:
                            raise ValueError(f"Script redirect limit reached ({max_redirects})")
                        current = normalize_url(urljoin(current, target))
                        continue
                    download.body_file = f"{result.profile}/scripts/script-{index:03d}.js"
                    for chunk in response.iter_bytes(chunk_size=8192):
                        remaining = max_body_bytes - len(body)
                        body.extend(chunk[:remaining])
                        if len(chunk) > remaining:
                            break
                    else:
                        download.body_truncated = False
                    if response.is_error:
                        download.error = f"HTTP {response.status_code}"
                    break
        except (httpx.HTTPError, httpx.InvalidURL, ValueError, UnicodeError, LookupError) as exc:
            download.error = f"{type(exc).__name__}: {exc}"
        except KeyboardInterrupt:
            download.error = "Interrupted by user"
            raise
        finally:
            if download.body_file is not None:
                (directory / f"script-{index:03d}.js").write_bytes(body)
                download.sampled_bytes = len(body)
                download.body_sha256 = hashlib.sha256(body).hexdigest()
            save_json(manifest, [asdict(item) for item in result.script_downloads])


def trace(
    url: str,
    profile: str,
    user_agent: str,
    *,
    timeout: float = 10,
    max_redirects: int = 10,
    max_body_bytes: int = 1_048_576,
    follow_meta: bool = True,
    output_dir: Path | None = None,
) -> Trace:
    result = Trace(profile, user_agent)
    if output_dir is not None:
        output_dir.mkdir(mode=0o700)
        save_json(output_dir / "trace.json", asdict(result))
    try:
        current = normalize_url(url)
        with httpx.Client(
            headers={"User-Agent": user_agent},
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            seen: set[tuple[str, str]] = set()
            for index in range(max_redirects + 1):
                request = client.build_request("GET", current)
                state = (str(request.url), request.headers.get("cookie", ""))
                if state in seen:
                    result.error = f"Redirect loop detected at {current}"
                    break
                seen.add(state)
                if output_dir is not None:
                    save_json(output_dir / f"request-{index:03d}.json", {
                        "timestamp": utc_now(),
                        "method": "GET",
                        "url": str(request.url),
                        "headers": request.headers.multi_items(),
                    })
                started = time.monotonic()
                with closing(client.send(request, stream=True)) as response:
                    headers_received = time.monotonic()
                    hop = Hop(
                        url=str(response.url),
                        status=response.status_code,
                        elapsed_ms=round((headers_received - started) * 1000, 2),
                        content_type=response.headers.get("content-type", ""),
                        server=response.headers.get("server", ""),
                        sampled_bytes=0,
                        body_truncated=True,
                        body_sha256=hashlib.sha256(b"").hexdigest(),
                        request_headers=request.headers.multi_items(),
                        response_headers=response.headers.multi_items(),
                    )
                    result.hops.append(hop)
                    body = bytearray()
                    try:
                        if index == 0:
                            result.network = network_identity(response)
                        if output_dir is not None:
                            save_json(output_dir / f"hop-{index:03d}.json", asdict(hop))
                        truncated = False
                        for chunk in response.iter_bytes(chunk_size=8192):
                            remaining = max_body_bytes - len(body)
                            body.extend(chunk[:remaining])
                            if len(chunk) > remaining:
                                truncated = True
                                break
                        hop.body_truncated = truncated
                        page = None
                        if "text/html" in hop.content_type.lower():
                            page = PageParser()
                            page.feed(bytes(body).decode(response.encoding or "utf-8", errors="replace"))
                            page.close()
                            hop.scripts = page.scripts
                            script_base = urljoin(str(response.url), page.base_url or str(response.url))
                            for script in hop.scripts:
                                if script.source_url is not None:
                                    script.source_url = urljoin(script_base, script.source_url)
                        target = None
                        if response.status_code in REDIRECT_STATUSES:
                            target = response.headers.get("location")
                            if target is None:
                                result.error = f"HTTP {response.status_code} without a Location header"
                                break
                            hop.redirect_type = "http"
                        elif follow_meta and page is not None:
                            target = page.target
                            if target is not None:
                                hop.redirect_type = "meta-refresh"
                        if target is None:
                            break
                        hop.redirect_to = urljoin(str(response.url), target)
                        current = normalize_url(hop.redirect_to)
                        if index == max_redirects:
                            result.error = f"Redirect limit reached ({max_redirects})"
                    finally:
                        hop.sampled_bytes = len(body)
                        hop.body_sha256 = hashlib.sha256(body).hexdigest()
                        if output_dir is not None:
                            hop.body_file = f"{profile}/hop-{index:03d}.body"
                            (output_dir / f"hop-{index:03d}.body").write_bytes(body)
                            save_json(output_dir / f"hop-{index:03d}.json", asdict(hop))
                            save_json(output_dir / "trace.json", asdict(result))
            if output_dir is not None:
                capture_scripts(client, result, output_dir, max_redirects, max_body_bytes)
    except (httpx.HTTPError, httpx.InvalidURL, ValueError, UnicodeError, LookupError) as exc:
        result.error = f"{type(exc).__name__}: {exc}"
    except KeyboardInterrupt:
        result.error = "Interrupted by user"
        result.interrupted = True
    finally:
        if not result.hops:
            result.network.error = "No HTTP response received; connected interface could not be inspected"
        result.finished_at = utc_now()
        if output_dir is not None:
            save_json(output_dir / "trace.json", asdict(result))
    return result


def signature(result: Trace) -> tuple:
    return (
        tuple(
            (
                hop.url,
                hop.status,
                hop.content_type,
                hop.server,
                hop.redirect_type,
                hop.redirect_to,
                hop.body_sha256,
                hop.body_truncated,
            )
            for hop in result.hops
        ),
        result.error,
    )


def compare(results: list[Trace]) -> dict:
    baseline = results[0] if results else None
    return {
        "baseline": baseline.profile if baseline else None,
        "different_profiles": [
            result.profile
            for result in results[1:]
            if signature(result) != signature(baseline)
        ],
        "mac_rotation": [
            {
                "previous_profile": previous.profile,
                "profile": current.profile,
                "status": (
                    "unknown" if not previous.network.mac or not current.network.mac
                    else "changed" if previous.network.mac != current.network.mac
                    else "unchanged"
                ),
            }
            for previous, current in zip(results, results[1:])
        ],
    }


def load_baseline(path: Path) -> tuple[Trace, str]:
    report_path = path / "report.json" if path.is_dir() else path
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if not isinstance(report, dict) or report.get("schema_version") != 1:
        raise ValueError("Unsupported baseline report schema")
    if not isinstance(report.get("url"), str):
        raise ValueError("Baseline must include its starting URL")
    traces = report.get("traces")
    if not isinstance(traces, list) or len(traces) != 1:
        raise ValueError("Baseline must contain exactly one captured platform")
    data = traces[0]
    if not isinstance(data, dict):
        raise ValueError("Invalid baseline trace")
    return Trace(**{
        **data,
        "network": NetworkIdentity(**data["network"]),
        "script_downloads": [
            ScriptDownload(**item) for item in data.get("script_downloads", [])
        ],
        "hops": [
            Hop(**{**hop, "scripts": [ScriptNote(**script) for script in hop["scripts"]]})
            for hop in data["hops"]
        ],
    }), report["url"]


def positive_timeout(value: str) -> float:
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("must be a finite number greater than zero")
    return number


def nonnegative_int(value: str) -> int:
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("must be zero or greater")
    return number


def positive_int(value: str) -> int:
    number = nonnegative_int(value)
    if number == 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number


def render_text(results: list[Trace], comparison: dict) -> str:
    lines = []
    for result in results:
        lines.extend([
            f"\n[{result.profile}] {result.user_agent}",
            f"  Network: {result.network.interface or 'unknown'}; "
            f"IP {result.network.local_ip or 'unknown'}; MAC {result.network.mac or 'unknown'}",
        ])
        if result.network.error:
            lines.append(f"  WARNING: MAC inspection: {result.network.error}")
        for index, hop in enumerate(result.hops):
            lines.append(f"  {index}: {hop.status} {hop.url} ({hop.elapsed_ms:.2f} ms)")
            if hop.redirect_to is not None:
                lines.append(f"     {hop.redirect_type} -> {hop.redirect_to}")
            lines.append(
                f"     {hop.content_type or '(no content type)'}; "
                f"body SHA-256 {hop.body_sha256[:16]}"
                f"{' (truncated sample)' if hop.body_truncated else ''}"
            )
            for script in hop.scripts:
                lines.append(
                    f"     SCRIPT [{script.script_type}]: "
                    f"{script.source_url if script.source_url is not None else '(inline)'}"
                )
                if script.inline_preview:
                    lines.append(f"       {script.inline_preview!r}")
        for download in result.script_downloads:
            lines.append(
                f"  SCRIPT DOWNLOAD: {download.source_url} -> "
                f"{download.body_file or '(not saved)'}"
                f"{' (truncated sample)' if download.body_truncated else ''}"
            )
            if download.error:
                lines.append(f"    WARNING: {download.error}")
        if result.error:
            lines.append(f"  ERROR: {result.error}")
    lines.append(f"\nBaseline: {comparison['baseline'] or 'not collected'}")
    if comparison.get("starting_urls_match") is False:
        lines.append(
            "NOTE: Starting URLs differ; differences may be caused by the probe URL, "
            "not just the user agent."
        )
    lines.append("Different: " + (", ".join(comparison["different_profiles"]) or "none"))
    for rotation in comparison["mac_rotation"]:
        lines.append(
            f"MAC {rotation['previous_profile']} -> {rotation['profile']}: {rotation['status']}"
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Trace HTTP and HTML meta-refresh redirects across user agents."
    )
    parser.add_argument(
        "url", nargs="?",
        help="Starting HTTP(S) URL (default: selected platform's connectivity-check URL)",
    )
    parser.add_argument("--platform", required=True, choices=PROFILES, help="One platform to capture")
    parser.add_argument(
        "--browser", action="store_true",
        help="Open an interactive browser for manual login (iphone or windows)",
    )
    parser.add_argument(
        "--monitor", action="store_true",
        help="With --browser, save a sensitive full HAR capture; off by default",
    )
    parser.add_argument(
        "--user-agent", help="Override the selected platform's built-in user agent",
    )
    parser.add_argument("--timeout", type=positive_timeout, default=10, help="Per-operation timeout in seconds")
    parser.add_argument("--max-redirects", type=nonnegative_int, help="HTTP mode only (default: 10)")
    parser.add_argument(
        "--max-body-bytes", type=positive_int,
        help="HTTP mode only (default: 1048576)",
    )
    parser.add_argument("--no-meta-refresh", action="store_true", help="Follow HTTP redirects only")
    parser.add_argument("--json", action="store_true", help="Write a JSON report to stdout")
    parser.add_argument(
        "--output", type=Path,
        help="New capture directory (default: captures/<UTC timestamp>); never overwritten",
    )
    parser.add_argument(
        "--compare-with", type=Path,
        help="Earlier capture directory or report.json to compare against",
    )
    args = parser.parse_args(argv)
    if args.monitor and not args.browser:
        parser.error("--monitor requires --browser")
    if args.browser:
        if args.platform not in {"iphone", "windows"}:
            parser.error("--browser supports --platform iphone or windows only")
        if (
            args.compare_with is not None or args.no_meta_refresh
            or args.max_redirects is not None or args.max_body_bytes is not None
        ):
            parser.error(
                "--compare-with, --no-meta-refresh, --max-redirects and "
                "--max-body-bytes are HTTP-mode options, not browser options"
            )
        if not args.monitor and (args.output is not None or args.json):
            parser.error("--output and --json require --monitor in browser mode")
    starting_url = args.url if args.url is not None else DEFAULT_URLS.get(args.platform)
    if starting_url is None:
        parser.error(
            f"No OS connectivity-check URL for {args.platform!r}; provide an explicit URL"
        )
    try:
        url = normalize_url(starting_url)
    except (ValueError, httpx.InvalidURL) as exc:
        parser.error(str(exc))
    if args.browser and not args.monitor:
        from .browser import run_browser

        return run_browser(
            url, args.platform, user_agent=args.user_agent, timeout=args.timeout,
        )
    user_agent = args.user_agent if args.user_agent is not None else PROFILES[args.platform]
    baseline = None
    if args.compare_with is not None:
        try:
            baseline, baseline_url = load_baseline(args.compare_with)
        except (OSError, ValueError, TypeError, KeyError) as exc:
            parser.error(f"Cannot load baseline: {exc}")
    output = (
        args.output or Path("captures") / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    ).resolve()
    try:
        output.mkdir(mode=0o700, parents=True, exist_ok=False)
    except OSError as exc:
        parser.error(f"Cannot create capture directory: {exc}")
    print(f"Saving capture to {output}", file=sys.stderr, flush=True)
    if args.browser:
        from .browser import run_browser

        return run_browser(
            url, args.platform, output_dir=output, user_agent=args.user_agent,
            timeout=args.timeout, print_json=args.json,
        )
    args.max_redirects = 10 if args.max_redirects is None else args.max_redirects
    args.max_body_bytes = 1_048_576 if args.max_body_bytes is None else args.max_body_bytes
    results: list[Trace] = []
    report = {
        "schema_version": 1,
        "url": url,
        "platform": args.platform,
        "baseline_capture": str(args.compare_with.resolve()) if args.compare_with else None,
        "started_at": utc_now(),
        "finished_at": None,
        "status": "running",
        "error": None,
        "environment": {"platform": sys.platform, "python": sys.version},
        "settings": {
            "user_agent": user_agent,
            "url_source": "explicit" if args.url is not None else "platform-default",
            "timeout": args.timeout,
            "max_redirects": args.max_redirects,
            "max_body_bytes": args.max_body_bytes,
            "follow_meta_refresh": not args.no_meta_refresh,
        },
        "comparison": compare(results),
        "traces": [],
    }

    def persist() -> None:
        report["comparison"] = compare(([baseline] if baseline is not None else []) + results)
        if baseline is not None:
            report["comparison"]["baseline_url"] = baseline_url
            report["comparison"]["starting_urls_match"] = baseline_url == url
        report["traces"] = [asdict(result) for result in results]
        save_json(output / "report.json", report)
        (output / "summary.txt").write_text(
            f"Status: {report['status']}\n"
            + (f"ERROR: {report['error']}\n" if report["error"] else "")
            + render_text(results, report["comparison"]),
            encoding="utf-8",
        )

    code = 0
    try:
        persist()
        print(f"Capturing {args.platform}...", file=sys.stderr, flush=True)
        result = trace(
            url, args.platform, user_agent, timeout=args.timeout,
            max_redirects=args.max_redirects, max_body_bytes=args.max_body_bytes,
            follow_meta=not args.no_meta_refresh, output_dir=output / args.platform,
        )
        results.append(result)
        code = 130 if result.interrupted else 1 if result.error else 0
        report["status"] = "interrupted" if code == 130 else "failed" if code else "completed"
    except KeyboardInterrupt:
        code = 130
        report["status"] = "interrupted"
        report["error"] = "Interrupted by user"
    except OSError as exc:
        print(f"ERROR: Could not persist capture: {exc}", file=sys.stderr)
        return 1
    report["finished_at"] = utc_now()
    try:
        persist()
    except OSError as exc:
        print(f"ERROR: Could not finalize capture: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print((output / "summary.txt").read_text(encoding="utf-8"), end="")
    print(f"Capture saved to {output}", file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())

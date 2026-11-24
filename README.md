# WiFi Captive Browser

A Python tool for opening captive portal login pages in an isolated browser,
tracing HTTP redirect chains, and comparing behavior across user-agent profiles.

Interactive mode supports an iPhone-like WebKit profile and Microsoft Edge.
Monitoring is off by default. HTTP mode saves diagnostic captures and can compare
them with an earlier run. The installed command remains `captive-tracer`.

## Quick start

Requires Python 3.12 or newer and [uv](https://docs.astral.sh/uv/getting-started/installation/).
Set up the project while connected to the internet:

```sh
git clone https://github.com/mcroomp/wificaptivebrowser.git
cd wificaptivebrowser
uv sync --frozen
uv run playwright install webkit
uv run --offline --frozen captive-tracer --browser --platform iphone
```

For Edge mode, install Microsoft Edge and use `--platform windows` instead.
On Linux, WebKit may also require system libraries; see
[Playwright's system dependencies](https://playwright.dev/python/docs/browsers#install-system-dependencies).
The Windows launcher is described below.

Only inspect networks and endpoints you are authorized to test. Captures may
contain credentials and private content; do not commit or publish them.

## Prepare before going offline

```sh
uv sync --frozen
uv run --offline --frozen captive-tracer --help
```

`uv sync` creates a project-local `.venv` and downloads dependencies while you
still have connectivity. No global installation or external service is needed
for collection. MAC inspection requires Linux and the `ip` command from
`iproute2`; HTTP tracing also runs on other platforms but reports an explicit
MAC-inspection warning.

### Windows (Command Prompt or double-click)

Install `uv` if needed, then prepare the Windows environment while online:

```bat
cd /d path\to\wificaptivebrowser
uv sync --frozen
captive-tracer.cmd --help
```

Dependencies are resolved through the Microsoft Python proxy feed configured in
`pyproject.toml`.

Virtual environments cannot be copied from Linux to Windows. If you brought
`.venv` from Linux, remove that environment first and let `uv sync` recreate it.

Double-click `captive-tracer.cmd`, or run it without arguments, to open an
interactive iPhone-like browser with monitoring off and keep the terminal open
afterward. The launcher works from any working directory and uses `uv` offline.
When arguments are supplied, they are forwarded as before, with Windows as the
fallback profile; include `--browser` for interactive mode or omit it for HTTP
tracing:

```bat
captive-tracer.cmd --platform iphone --output "captures\iphone-01"
captive-tracer.cmd --output "captures\windows-01" --compare-with "captures\iphone-01"
```

The launcher preserves the Python exit code. Run `uv sync --frozen` again while
online if dependencies are missing; it does not download packages during collection.
Windows HTTP tracing works without administrator access; MAC inspection still
reports an unsupported-platform warning.

## Interactive browser login (optional monitoring)

Use a real browser when you need to run JavaScript and complete login yourself.
Install dependencies and the iPhone-mode browser while online:

```bat
uv sync --frozen
uv run playwright install webkit
```

Windows mode uses your installed Microsoft Edge. iPhone mode uses Playwright's
WebKit browser and iPhone 13 device preset (not actual iOS Safari or Apple's
captive-login window). It emulates the user agent, screen, viewport, and touch;
it does not emulate the entire OS, network stack, or browser fingerprint.
Because Windows WebKit leaves `navigator.platform` and `navigator.maxTouchPoints`
unchanged by the preset, iPhone mode explicitly sets them to `iPhone` and `5`
before page scripts run. This is basic, detectable emulation, not a guarantee
that every browser property matches a real iPhone.
Windows mode keeps Edge's native identity rather than the HTTP tracer's fixed
user-agent string. `--user-agent` can override either, but may make the identity
inconsistent with other browser properties.

Open either profile without monitoring:

```bat
captive-tracer.cmd --browser --platform windows
captive-tracer.cmd --browser --platform iphone
```

The browser uses a fresh, isolated session, not your personal browser profile.
Click and type normally: JavaScript, cookies, CSRF fields, and form submissions
are handled by the browser. **Keep the terminal open. When finished, press Enter
in the terminal** to close the browser and finalize the session. An initial
navigation error is printed but leaves the browser open so you can retry manually.
Browser startup never downloads missing engines automatically.

**Monitoring is off by default:** the utility writes no capture files in browser
mode unless you add `--monitor`:

```bat
captive-tracer.cmd --browser --platform iphone --monitor --output "captures\iphone-browser-01"
```

With monitoring, the new output directory contains `report.json` with the actual
browser identification properties and `network.har` with requests, responses,
and response bodies, including scripts the browser loads. **HAR files can include
passwords, form data, session cookies, tokens, and private page content. Keep
them private.** Unlike HTTP-mode samples, HAR bodies are not size-bounded, and
the HAR is finalized on graceful context closure; a forced kill or browser crash
can lose the recording. The browser may contact third-party services referenced
by the portal. Nothing is uploaded by the utility.

`--output` and `--json` require `--monitor` in browser mode. HTTP-only options
`--compare-with`, `--no-meta-refresh`, `--max-redirects`, and `--max-body-bytes`
are rejected with `--browser`; browser redirects and page scripts run normally.
Browser completion means the session closed, not that login succeeded. Browser
HAR captures are separate from HTTP trace reports and cannot be compared using
`--compare-with`.

## Collect one platform at a time

Connect to the test network and run from this project directory:

```sh
uv run --offline --frozen captive-tracer --platform iphone --output captures/iphone-01
```

After any manual network/MAC change, reconnect to the test network and capture
Windows using its own connectivity-check URL:

```sh
uv run --offline --frozen captive-tracer --platform windows --output captures/windows-01 \
  --compare-with captures/iphone-01
```

Each invocation requires exactly one `--platform` and makes only that platform's
requests. `iphone` uses an iPhone Safari user agent; `windows` uses Windows Edge.
These are HTTP user-agent profiles, **not actual OS/network-stack emulation**.
The comparison reports chain/body differences and MAC `changed`, `unchanged`,
or `unknown`. A changed local MAC alone does not prove that the portal considers
the client new. Without `--compare-with`, the run simply captures one platform.

When no URL is given, the platform selects a common HTTP connectivity-check
endpoint:

| Platform | Default starting URL |
| --- | --- |
| `iphone`, `apple-captive` | `http://captive.apple.com/hotspot-detect.html` |
| `windows` | `http://www.msftconnecttest.com/connecttest.txt` |
| `android` | `http://connectivitycheck.gstatic.com/generate_204` |

These are probe URLs, not portal login URLs: the network may intercept them and
redirect to its portal. Actual OS probes can vary with version, vendor, region,
and managed configuration. Browser/tool profiles `chrome`, `firefox`, and `curl`
have no OS probe default here and require an explicit URL.

Override any default with a positional URL:

```sh
uv run --offline --frozen captive-tracer http://neverssl.com/ --platform iphone
```

Different platform defaults mean different starting URLs, so a baseline
comparison explicitly flags this in the report and summary. Different probe
URLs alone make chains differ; this is not proof of user-agent discrimination.
To isolate the user agent, supply the same explicit URL for both platforms.

The collector does not rotate MACs or change network settings. Cookies are fresh
per invocation, but a portal may still recognize the device by MAC/IP or other
network state. To isolate just user-agent behavior, keep other conditions
constant; to test a fresh device identity, change it separately and inspect the
recorded MAC. Use distinct output directories for repeat runs (e.g. `iphone-02`).

Alternatively invoke `.venv/bin/captive-tracer` directly on Linux/macOS, or
`.venv\Scripts\captive-tracer.exe` on Windows. After setup, this bypasses `uv`
entirely and does not need connectivity beyond the test network.

Only test networks and endpoints you are authorized to inspect. Starting URLs
are contacted when you run the commands, even without general internet access.

## Saved captures and later analysis

Every HTTP-mode run logs automatically to a new `captures/<UTC timestamp>` directory,
or the directory given by `--output`. Existing directories are never overwritten.
No telemetry or external analysis service is used.

Each directory contains:

```text
report.json                   # Run settings, platform, timestamps, hops, comparison
summary.txt                   # Human-readable trace, errors, and script notes
iphone/                       # Or windows/, etc.
  trace.json                  # Per-platform trace, updated as hops complete
  request-000.json             # Request URL, method, timestamp, all sent headers
  hop-000.json                 # Status, headers, timing, redirect target, script notes
  hop-000.body                 # Decompressed response body sample (binary-safe)
  scripts/
    urls.txt                   # Unique external script URLs found in sampled HTML
    manifest.json              # Download results and local file mapping
    script-000.js              # Bounded response sample; never executed
  ...                         # Subsequent requests and hops
```

Headers include cookies and authorization-related portal data. Captures contain
MAC/IP identity, URLs with possible tokens, and response content. Keep them
private and review them before sharing. Capture directories are git-ignored.
On Unix the collector creates the capture directory with owner-only permissions.

The initial report is saved before requests; request metadata is saved before
each request, and hops are checkpointed as they complete. Connection errors,
redirect errors, and Ctrl+C are persisted. A forced kill/power failure can leave
an incomplete run; completed hop files and per-platform traces remain useful.

Use `--compare-with` to compare captures, or inspect the saved JSON, summaries,
response bodies, scripts, and network identity locally.
Keep the whole directories, not just console output. Inline script
source is in the saved HTML body. Referenced external scripts are downloaded
after the redirect trace, without execution, into the platform's `scripts`
directory. A `urls.txt` list and `manifest.json` map source/final URLs to local
`script-000.js` files, HTTP statuses, sample sizes/hashes, truncation, and errors.
URLs are deduplicated per capture and resolved against the page's first
`<base href>` when present. Downloads use the same user agent and session cookies,
and the same timeout, redirect limit, and per-file body-size limit as the trace.
They may contact other hosts named by the page. Download failures are recorded
as warnings without failing an otherwise successful redirect trace.

## What it does

- Sends GET requests as one explicitly selected platform per run.
- Follows relative/absolute HTTP 301/302/303/307/308 redirects and HTML
  meta-refresh redirects, recording each hop and time to response headers.
- Uses a fresh cookie jar per run, preserving cookies within its chain.
- Records the first connection's local IP, interface, and current MAC for each
  attempt on Linux with `iproute2`. With a baseline, flags the MAC as `changed`,
  `unchanged`, or `unknown`. This observes rotation; it does not rotate MACs or
  alter network settings. Missing tooling, loopback/tunnel interfaces, unsupported
  platforms, and unavailable connection details produce explicit inspection
  warnings, not made-up MACs. Inspection failures do not fail an HTTP trace.
- Notes HTML script tags with resolved external script URLs and inline previews
  (up to 200 characters) plus SHA-256 hashes in JSON. External scripts are
  downloaded alongside CLI captures but never executed. Notes are limited to
  the captured HTML sample; a script cut off
  by the sample boundary has only a partial preview/hash.
- Detects repeated URL/cookie states and enforces a redirect limit.
- Reports status, destination, content type, server, and sampled-body SHA-256
  in JSON. Text output gives a compact trace.
- Optionally compares a chain against an earlier capture, including body hashes but
  excluding timings. HTTP error statuses are recorded, not treated as transport
  failures. Network errors, invalid redirects, loops, and limits exit with code 1;
  CLI input errors exit with code 2, and Ctrl+C exits with code 130.
  Differences or unchanged/unknown MACs alone do not fail a run.

Platforms: `iphone`, `windows`, `chrome`, `firefox`, `android`, `apple-captive`,
and `curl`. `--user-agent "MyProbe/1.0"` overrides the chosen platform's
user-agent string. `--json` also prints the saved report to stdout; progress
goes to stderr.

Options include `--timeout 10` (per network operation, not total trace time),
`--max-redirects 10`, `--max-body-bytes 1048576`, and `--no-meta-refresh`.
Meta refreshes are followed immediately without waiting for their delay.
Bodies are bounded to 1 MiB per hop by default, not unlimited full packet captures.
Increase `--max-body-bytes` if needed. Truncated or incomplete samples are flagged.
Dynamic content can produce differences unrelated to the user agent; changes
past the sample limit are not detected.

## Limits

By default this is an HTTP tracer, not a browser: it does not execute JavaScript, submit login
forms, fetch non-script subresources, or emulate TLS/browser fingerprints.
Only explicit `<script src>` references in sampled HTML are downloaded, not
JavaScript imports, dynamically generated URLs, or scripts referenced by scripts.
Files may contain error pages or portal responses rather than JavaScript; check
the manifest before using them. Profiles select
the User-Agent header and, unless overridden, the connectivity-check URL.
They do not emulate other OS-specific probe headers or the full detection
sequence (such as DNS checks or parallel HTTPS probes). HTTPS certificates are
verified; use an HTTP starting URL to observe typical portal interception.
Environment proxy settings and `.netrc` credentials are intentionally ignored so
requests go directly to the network being tested.

MAC inspection observes the host-side interface used by the first HTTP
connection, not necessarily what the access point sees. Under WSL, containers,
VMs, VPNs, or NAT this may be a virtual interface, and rotating a physical
adapter may not change the reported MAC. Use native Linux on the Wi-Fi interface
for direct observation. Different user agents do not themselves rotate MACs.

## Tests

```sh
uv run --offline --frozen python -m unittest discover -s tests -v
```

Tests use a local HTTP server; they do not contact external websites.

To also verify both real browser engines against a local JavaScript/form-login
fixture (opens temporary browser windows), install Edge and WebKit, then run:

```bat
set CAPTIVE_BROWSER_TESTS=1
uv run --offline --frozen python -m unittest discover -s tests -p test_browser.py -v
```

The default test suite uses local fixtures and mocked browsers. Real-browser
integration tests are opt-in and require both browser engines.

## License

[MIT](LICENSE).

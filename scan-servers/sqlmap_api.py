import os
import re
import shutil
import socket
import urllib.parse
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from security import sanitize_target, sanitize_options, sanitize_cookie
from runner import run_streaming, pause_process, resume_process

app = FastAPI(title="SQLmap API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

TIMEOUT_STEALTH = 1800
TIMEOUT_NORMAL  = 1200

# Persistent per-host session storage. Re-using the same directory across
# scans of the same host lets sqlmap restore its session.sqlite cache so
# heuristics, crawl results and previously-found injection points survive
# between runs (this is what "session support" gives us).
SESSIONS_ROOT = os.path.expanduser("~/.sqlmap-sessions")

# Flags we always control ourselves. Anything the caller passes via
# `options` that collides with one of these is dropped so it cannot
# weaken the scan profile or break session/output handling.
PROTECTED_FLAGS = {
    "--level", "--risk", "--threads", "--timeout",
    "--retries", "--time-sec", "--technique", "--batch",
    "--delay", "--output-dir",
    "-v", "--keep-alive", "--random-agent", "--tamper",
    "--text-only", "--titles", "--parse-errors",
    "--smart", "--forms", "--crawl", "--dbs",
    # We always inject `--cookie` ourselves from the dedicated `cookie`
    # field, so silently drop a `--cookie=` someone tucked into options
    # to avoid sqlmap getting two of them.
    "--cookie",
}

# Patterns we accept as positive evidence even if sqlmap doesn't print
# its formal "is vulnerable" verdict. These cover the three detection
# layers we want on top of "HTTP 200 = ok":
#   1. response diff   -> sqlmap reports different page/text/title
#   2. content length  -> sqlmap reports different content lengths
#   3. error patterns  -> DBMS error fingerprints in the response
HEURISTIC_PATTERNS = [
    re.compile(r"heuristic\s*\(basic\)\s*test\s*shows.*?injectable", re.I),
    re.compile(r"parameter\s+'[^']+'\s+might\s+be\s+injectable", re.I),
    re.compile(r"reflective\s+value\(s\)\s+found", re.I),
]
RESPONSE_DIFF_PATTERNS = [
    re.compile(r"different\s+(?:page|response|title)s?\b", re.I),
    re.compile(r"target\s+url\s+content\s+is\s+different", re.I),
]
CONTENT_LENGTH_PATTERNS = [
    re.compile(r"different\s+content\s*-?\s*length", re.I),
    re.compile(r"length\s+difference\s+detected", re.I),
    re.compile(r"\bcontent\s+length\s+differs?\b", re.I),
]
CONNECTION_ERROR_PATTERNS = [
    re.compile(r"unable to connect to (?:the )?target", re.I),
    re.compile(r"connection timed out", re.I),
    re.compile(r"connection refused", re.I),
    re.compile(r"name or service not known", re.I),
    re.compile(r"network is unreachable", re.I),
    re.compile(r"\[CRITICAL\].*unable to connect", re.I),
    re.compile(r"sqlmap is going to retry the request", re.I),
    re.compile(r"too many connection problems", re.I),
]
DBMS_ERROR_PATTERNS = [
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"warning.*?\bmysql_", re.I),
    re.compile(r"unclosed\s+quotation\s+mark", re.I),
    re.compile(r"ora-\d{5}", re.I),
    re.compile(r"microsoft (?:ole db|sql server|odbc).*?error", re.I),
    re.compile(r"postgresql.*?error", re.I),
    re.compile(r"sqlite.*?error", re.I),
    re.compile(r"\bsqlstate\[", re.I),
    re.compile(r"pdoexception", re.I),
]


class ScanRequest(BaseModel):
    target: str
    options: str = ""
    stealth: bool = True
    scan_id: str | None = None
    # Optional HTTP cookie string (e.g. "session=abc123" or
    # "session=abc; csrf=xyz"). When supplied we forward it as
    # `--cookie="..."` so sqlmap impersonates an authenticated
    # user — same effect as accepting the "use server cookie" prompt
    # in the manual workflow.
    cookie: str = ""


# Match a bare token like `session=ziy5RMoix...` or `phpsessid=abc` so
# we can recognise it whether the user typed it in the dedicated cookie
# field or inside the options box. Cookie names must start with a
# letter/digit/underscore — never a hyphen — so `--level=5` and other
# CLI flags do NOT accidentally get extracted as cookies.
_BARE_COOKIE_PAIR_RE = re.compile(
    r"^[a-zA-Z0-9_][a-zA-Z0-9_\-]*\s*=\s*[A-Za-z0-9_\-\.%~]+"
    r"(?:\s*;\s*[a-zA-Z0-9_][a-zA-Z0-9_\-]*\s*=\s*[A-Za-z0-9_\-\.%~]+)*$"
)


def _normalise_cookie(raw: str) -> str:
    """
    Turn whatever the user typed into a plain `name=value;name=value`
    cookie string sqlmap can consume.

    Accepts:
      * `session=abc123`              -> returned as-is
      * `--cookie=session=abc`        -> strips the `--cookie=` prefix
      * `--cookie session=abc`        -> same, with a space
      * `Cookie: session=abc`         -> strips the header prefix
      * a bare token like `abc123`    -> assumes it's a session value
                                         and wraps it as `session=abc123`
    """
    raw = (raw or "").strip()
    if not raw:
        return ""
    # Strip surrounding quotes the user might have copy-pasted in.
    if (raw.startswith('"') and raw.endswith('"')) or (
        raw.startswith("'") and raw.endswith("'")
    ):
        raw = raw[1:-1].strip()
    # Strip `Cookie:` header prefix.
    low = raw.lower()
    if low.startswith("cookie:"):
        raw = raw[len("cookie:"):].strip()
    # Strip `--cookie=` / `--cookie ` prefix.
    if low.startswith("--cookie="):
        raw = raw[len("--cookie="):].strip()
    elif low.startswith("--cookie "):
        raw = raw[len("--cookie "):].strip()
    # Strip surrounding quotes again post-prefix-strip.
    if (raw.startswith('"') and raw.endswith('"')) or (
        raw.startswith("'") and raw.endswith("'")
    ):
        raw = raw[1:-1].strip()
    if not raw:
        return ""
    # Bare token without `=` — assume it's a session value.
    if "=" not in raw:
        return f"session={raw}"
    return raw


def _extract_cookie_from_options(options: str) -> tuple[str, str]:
    """
    If the user typed something like `--cookie=session=abc` (or just
    `session=abc`) into the Options box, pull it out so we can feed it
    to sqlmap via the proper `--cookie` arg and return the cleaned
    options string for the rest of the parser.

    Returns (cleaned_options, extracted_cookie_or_empty).
    """
    if not options:
        return "", ""
    tokens = options.split()
    keep: list[str] = []
    extracted = ""
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        low = tok.lower()
        if low.startswith("--cookie="):
            extracted = tok[len("--cookie="):]
            i += 1
            continue
        if low == "--cookie" and i + 1 < len(tokens):
            extracted = tokens[i + 1]
            i += 2
            continue
        # Bare `session=...` / `phpsessid=...` / etc.
        if not extracted and _BARE_COOKIE_PAIR_RE.match(tok):
            extracted = tok
            i += 1
            continue
        keep.append(tok)
        i += 1
    return " ".join(keep), extracted


def _base_flag(opt: str) -> str:
    return opt.split("=")[0]


def _safe_host_dir(host: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", host or "default")
    return safe[:120] or "default"


def _check_reachability(url: str) -> tuple[bool, str]:
    """Open a quick TCP connection to host:port. Returns (ok, message)."""
    try:
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname
        if not host:
            return False, f"Could not parse host from URL: {url}"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror as e:
            return False, f"DNS lookup failed for '{host}': {e}"
        with socket.create_connection((ip, port), timeout=8) as _s:
            return True, f"TCP {host}:{port} ({ip}) reachable"
    except (socket.timeout, TimeoutError):
        return False, (
            f"TCP connection to {host}:{port} timed out after 8s. "
            "The target is unreachable from this machine — check your "
            "network/firewall/VPN. SQLmap cannot inject anything if it "
            "cannot connect."
        )
    except OSError as e:
        return False, f"TCP connection to {host}:{port} failed: {e}"


def _augment_findings_summary(output: str) -> str:
    """
    Append a short evidence summary so the gateway/UI can pick up
    findings even when sqlmap does not print its formal verdict —
    using response-diff, content-length and DBMS error signals.
    """
    if not output:
        return output

    def _hits(patterns):
        n = 0
        for p in patterns:
            n += len(p.findall(output))
        return n

    heur = _hits(HEURISTIC_PATTERNS)
    diff = _hits(RESPONSE_DIFF_PATTERNS)
    clen = _hits(CONTENT_LENGTH_PATTERNS)
    errs = _hits(DBMS_ERROR_PATTERNS)
    conn = _hits(CONNECTION_ERROR_PATTERNS)

    lines = [
        "",
        "=" * 70,
        "[gateway] Detection summary (beyond HTTP 200 == ok)",
        f"  - Heuristic injectable hints : {heur}",
        f"  - Response-diff signals      : {diff}",
        f"  - Content-length anomalies   : {clen}",
        f"  - DBMS error patterns        : {errs}",
        f"  - Connection / reach errors  : {conn}",
    ]
    if (heur + diff + clen + errs) > 0 and "is vulnerable" not in output.lower():
        lines.append(
            "  -> Heuristic evidence found but sqlmap did not confirm "
            "exploitation. Treat as 'possible injection — manual review'."
        )
    if conn > 0 and (heur + diff + clen + errs) == 0:
        lines += [
            "",
            "[!] NETWORK PROBLEM — sqlmap could not reach the target.",
            "    The scan is NOT failing because of a sqlmap bug or a",
            "    missing flag. Your machine cannot open a TCP connection",
            "    to the target host.",
            "",
            "    Try from your terminal:",
            "        curl -v --max-time 10 <target-url>",
            "    If that also times out, the issue is one of:",
            "      * the target site is currently down",
            "      * your ISP / firewall / VPN is blocking outbound HTTP",
            "      * you are on a network that requires an HTTP proxy",
            "        (run sqlmap with --proxy=http://host:port or",
            "         --proxy-file=/path/to/list.txt to route through one)",
            "      * the target only accepts requests from another region",
            "",
            "    Pick a target you can actually reach (e.g. a local lab,",
            "    DVWA, juice-shop, or your own staging host) and retry.",
        ]
    lines.append("=" * 70)
    return output + "\n" + "\n".join(lines) + "\n"


@app.get("/health")
def health():
    sqlmap_path = shutil.which("sqlmap")
    return {
        "status": "ok",
        "tool": "sqlmap",
        "installed": sqlmap_path is not None,
        "path": sqlmap_path,
        "sessions_root": SESSIONS_ROOT,
    }


@app.post("/scan")
def run_sqlmap(req: ScanRequest):
    print(
        f"\n[SQLMAP-API] /scan request received: target={req.target!r} "
        f"stealth={req.stealth} scan_id={req.scan_id}",
        flush=True,
    )

    try:
        target = sanitize_target(req.target)
        raw_opts = req.options.strip() if req.options.strip() else ""
        options = sanitize_options(raw_opts) if raw_opts else ""
        # Pull a cookie out of the options string if the user typed it
        # there (e.g. `session=abc`), then merge with the dedicated
        # `cookie` field. The dedicated field wins if both are set.
        options, cookie_from_opts = _extract_cookie_from_options(options)
        cookie_raw = req.cookie.strip() or cookie_from_opts
        cookie = sanitize_cookie(_normalise_cookie(cookie_raw)) if cookie_raw else ""
    except ValueError as e:
        print(f"[SQLMAP-API] sanitize error: {e}", flush=True)
        raise HTTPException(status_code=400, detail=str(e))

    sqlmap_path = shutil.which("sqlmap")
    if not sqlmap_path:
        print("[SQLMAP-API] sqlmap binary NOT FOUND in PATH", flush=True)
        raise HTTPException(
            status_code=500,
            detail="sqlmap is not installed. Install it with: sudo apt install sqlmap",
        )
    print(f"[SQLMAP-API] sqlmap binary: {sqlmap_path}", flush=True)

    url = target if "://" in target else f"http://{target}"
    parsed = urllib.parse.urlparse(url)
    has_query = bool(parsed.query) and "=" in parsed.query

    # Pre-flight reachability check — non-blocking. The probe can fail
    # on networks where sqlmap (using HTTP/keep-alive/random agents)
    # would still succeed, so we log a warning and keep going instead
    # of aborting the scan.
    pre_flight_warning = ""
    ok, reach_msg = _check_reachability(url)
    print(f"[SQLMAP-API] pre-flight: ok={ok} msg={reach_msg}", flush=True)
    if not ok and url.startswith("https://"):
        http_url = "http://" + url[len("https://"):]
        ok2, reach_msg2 = _check_reachability(http_url)
        print(
            f"[SQLMAP-API] HTTP fallback pre-flight: ok={ok2} msg={reach_msg2}",
            flush=True,
        )
        if ok2:
            url = http_url
            parsed = urllib.parse.urlparse(url)
            has_query = bool(parsed.query) and "=" in parsed.query
            reach_msg = f"{reach_msg}\n[gateway] Falling back to HTTP: {reach_msg2}"
            ok = True
    if not ok:
        pre_flight_warning = (
            f"[PRE-FLIGHT WARNING] {reach_msg}\n"
            f"[gateway] TCP probe failed but running sqlmap anyway — "
            f"sqlmap will report the real connection error if the host "
            f"is truly unreachable.\n"
        )
        print(pre_flight_warning, flush=True)

    # Per-host persistent session/output directory. sqlmap stores
    # session.sqlite + log files inside this folder, so the next run
    # against the same host can restore previous heuristics, crawl
    # results, and confirmed injection points.
    # sqlmap auto-creates a per-target subfolder inside --output-dir and
    # stores session.sqlite there. Using SESSIONS_ROOT directly as
    # --output-dir ensures that sqlmap creates/uses
    # SESSIONS_ROOT/<hostname>/session.sqlite, giving us stable
    # session persistence across runs.
    os.makedirs(SESSIONS_ROOT, exist_ok=True)

    # User-requested baseline profile.
    stdbuf_path = shutil.which("stdbuf")
    common = []
    if stdbuf_path:
        common.extend([stdbuf_path, "-oL", "-eL"])

    common.extend([
        sqlmap_path,
        "-u", url,
        "--batch",
        "--random-agent",
        "--tamper=space2comment",
        "--level=5",
        "--risk=3",
        # Better detection: response diff + title diff + DBMS error
        # parsing instead of relying on "HTTP 200 == ok".
        "--text-only",
        "--titles",
        "--parse-errors",
        "--smart",
        # Persistent session so repeat scans actually progress instead
        # of restarting from scratch every time. sqlmap stores
        # session.sqlite under <output-dir>/<target> automatically.
        "--output-dir", SESSIONS_ROOT,
        "-v", "2",
        "--keep-alive",
        "--timeout=30",
        "--retries=2",
    ]

    if req.stealth:
        cmd = common + [
            "--threads=2",
            "--time-sec=5",
            "--delay=1",
        ]
    else:
        cmd = common + [
            "--threads=5",
            "--time-sec=5",
        ]

    # Always test for DBs against the supplied URL AND crawl/scan
    # forms on the host. This way URLs with parameters AND general
    # URLs (no query string) both get a proper inspection — no more
    # "one path yes, the other no".
    cmd.append("--dbs")
    cmd.extend(["--forms", "--crawl=2"])
    # Always exclude logout/reset/delete links to avoid losing the session.
    cmd.append("--crawl-exclude=logout|signout|delete|reset|change-password")

    # Authenticated session support — same effect as accepting the
    # "use server cookie" prompt in the interactive workflow. When a
    # cookie is supplied sqlmap re-uses it on every request, so labs
    # like PortSwigger that gate the vulnerable endpoint behind a
    # session can actually be reached. We pass the value as a single
    # argv entry (no shell quoting needed because we use exec, not
    # shell=True).
    if cookie:
        cmd.append(f"--cookie={cookie}")
        print(
            f"[SQLMAP-API] using cookie ({len(cookie)} chars): "
            f"{cookie[:24]}{'...' if len(cookie) > 24 else ''}",
            flush=True,
        )

    # Merge user-supplied extra options without letting them override
    # any of the protected flags above.
    if options:
        # Pre-process PROTECTED_FLAGS to handle both --flag and --flag=value forms
        protected_bases = set()
        for f in PROTECTED_FLAGS:
            protected_bases.add(f)
            if f.startswith("--"):
                protected_bases.add(f.split("=")[0])

        current_cmd_bases = {_base_flag(o) for o in cmd}

        for o in options.split():
            if not ((o.startswith("--") or o.startswith("-")) and len(o) < 60):
                continue
            base = _base_flag(o)
            if base in protected_bases or base in current_cmd_bases:
                print(f"[SQLMAP-API] dropping protected/duplicate option: {o}", flush=True)
                continue
            cmd.append(o)

    timeout = TIMEOUT_STEALTH if req.stealth else TIMEOUT_NORMAL

    print(
        f"[SQLMAP-API] launching sqlmap (timeout={timeout}s): {' '.join(cmd)}",
        flush=True,
    )
    try:
        output, rc = run_streaming(
            cmd, timeout=timeout, label="SQLMAP", scan_id=req.scan_id,
        )
        if not output.strip():
            output = "sqlmap produced no output."
        print(f"[SQLMAP-API] sqlmap finished rc={rc}", flush=True)
    except Exception as e:
        output = f"Error running sqlmap: {type(e).__name__}: {str(e)}"
        print(f"[SQLMAP-API] EXCEPTION launching sqlmap: {e}", flush=True)

    # Auto-fallback to HTTP if HTTPS handshake failed.
    ssl_failed = (
        url.startswith("https://")
        and (
            "can't establish SSL connection" in output
            or "SSL connection error" in output
        )
    )
    if ssl_failed:
        http_url = "http://" + url[len("https://"):]
        retry_cmd = [http_url if c == url else c for c in cmd]
        retry_note = (
            f"\n\n[gateway] HTTPS connection to {url} failed (SSL timeout). "
            f"Retrying over HTTP: {http_url}\n"
        )
        try:
            retry_output, rc = run_streaming(
                retry_cmd, timeout=timeout, label="SQLMAP-HTTP", scan_id=req.scan_id,
            )
            output = output + retry_note + retry_output
            url = http_url
            cmd = retry_cmd
        except Exception as e:
            output = (
                output
                + retry_note
                + f"Error running sqlmap retry: {type(e).__name__}: {str(e)}"
            )

    output = _augment_findings_summary(output)
    if pre_flight_warning:
        output = pre_flight_warning + "\n" + output

    host = parsed.hostname or "default"
    host_dir = os.path.join(SESSIONS_ROOT, _safe_host_dir(host))

    return {
        "tool": "sqlmap",
        "target": target,
        "command": " ".join(cmd),
        "output": output,
        "status": "completed",
        "session_dir": host_dir,
    }


@app.post("/pause/{scan_id}")
def pause(scan_id: str):
    ok, msg = pause_process(scan_id)
    if not ok:
        raise HTTPException(status_code=404, detail=msg)
    return {"ok": True, "scan_id": scan_id, "message": msg}


@app.post("/resume/{scan_id}")
def resume(scan_id: str):
    ok, msg = resume_process(scan_id)
    if not ok:
        raise HTTPException(status_code=404, detail=msg)
    return {"ok": True, "scan_id": scan_id, "message": msg}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)

"""
fingerprints.py
===============

Extract software fingerprints (vendor:product:version) from the raw output
produced by NMAP, NIKTO, SQLMAP and FFUF. Output is a list of
matcher.Fingerprint objects ready to be fed to the matching engine.

The extractor is intentionally conservative: it only returns fingerprints
where it is confident about both the product *and* the version. Empty or
ambiguous mentions are skipped to avoid false-positive CVE matches.
"""

from __future__ import annotations

import re
from typing import Iterable

from matcher import Fingerprint


# ---------------------------------------------------------------
# Product name -> (CPE vendor, CPE product) mapping
# Keys are lowercased substrings we look for in tool output.
# ---------------------------------------------------------------
PRODUCT_MAP: dict[str, tuple[str, str]] = {
    # Web servers
    "apache":          ("apache",    "http_server"),
    "apache httpd":    ("apache",    "http_server"),
    "httpd":           ("apache",    "http_server"),
    "nginx":           ("nginx",     "nginx"),
    "iis":             ("microsoft", "iis"),
    "lighttpd":        ("lighttpd",  "lighttpd"),
    "tomcat":          ("apache",    "tomcat"),
    "jetty":           ("eclipse",   "jetty"),
    "caddy":           ("caddyserver","caddy"),

    # CMSs & Web Apps
    "wordpress":       ("wordpress", "wordpress"),
    "drupal":          ("drupal",    "drupal"),
    "joomla":          ("joomla",    "joomla!"),
    "magento":         ("magento",   "magento"),
    "ghost":           ("ghost",     "ghost"),
    "strapi":          ("strapi",    "strapi"),
    "nextcloud":       ("nextcloud", "nextcloud"),
    "owncloud":        ("owncloud",  "owncloud"),
    "roundcube":       ("roundcube", "roundcube_webmail"),

    # Dev & CI/CD
    "gitlab":          ("gitlab",    "gitlab"),
    "jenkins":         ("jenkins",   "jenkins"),
    "gitea":           ("gitea",     "gitea"),
    "confluence":      ("atlassian", "confluence_server"),
    "jira":            ("atlassian", "jira"),

    # Languages / runtimes
    "php":             ("php",       "php"),
    "python":          ("python",    "python"),
    "node.js":         ("nodejs",    "node.js"),
    "nodejs":          ("nodejs",    "node.js"),
    "ruby":            ("ruby-lang", "ruby"),

    # Crypto & Auth
    "openssl":         ("openssl",   "openssl"),
    "keycloak":        ("keycloak",  "keycloak"),

    # JS libraries
    "jquery":          ("jquery",    "jquery"),
    "bootstrap":       ("getbootstrap", "bootstrap"),
    "angularjs":       ("angularjs", "angular.js"),
    "react":           ("facebook",  "react"),
    "vue":             ("vuejs",     "vue.js"),

    # Databases
    "mysql":           ("mysql",     "mysql"),
    "mariadb":         ("mariadb",   "mariadb"),
    "postgresql":      ("postgresql","postgresql"),
    "postgres":        ("postgresql","postgresql"),
    "mssql":           ("microsoft", "sql_server"),
    "microsoft sql server": ("microsoft", "sql_server"),
    "oracle":          ("oracle",    "database"),
    "redis":           ("redislabs", "redis"),
    "mongodb":         ("mongodb",   "mongodb"),

    # Mail Servers
    "exim":            ("exim",      "exim"),
    "postfix":         ("postfix",   "postfix"),
    "dovecot":         ("dovecot",   "dovecot"),

    # Infrastructure & Networking
    "openssh":         ("openbsd",   "openssh"),
    "ssh":             ("openbsd",   "openssh"),
    "samba":           ("samba",     "samba"),
    "fortios":         ("fortinet",  "fortios"),
    "fortigate":       ("fortinet",  "fortios"),
    "pan-os":          ("paloaltonetworks", "pan-os"),
}

# Sorted longest-first so "apache httpd" matches before "apache" etc.
_PRODUCT_KEYS_LONGEST_FIRST = sorted(PRODUCT_MAP.keys(), key=len, reverse=True)

# Reasonable version pattern: 1, 1.2, 1.2.3, 1.2.3a, 1.2.3-rc1, 1.0.1f
_VERSION_RE = re.compile(r"\b(\d+(?:\.\d+){0,4}[A-Za-z]?(?:[-_.][A-Za-z0-9]+)?)\b")

# Smart Keywords for non-software findings
# Patterns for sensitive file exposure (FFUF)
_SENSITIVE_PATTERNS = {
    "CRITICAL": [
        r"\.env$", r"\.git/", r"config\.php\.bak$", r"backup\.sql$",
        r"wp-config\.php\.bak$", r"\.ssh/", r"id_rsa", r"shadow$"
    ],
    "HIGH": [
        r"/admin\b", r"/phpmyadmin\b", r"/vnc\b", r"/console\b", r"/dashboard\b",
        r"/config$", r"/settings$", r"/setup$", r"\.htaccess$"
    ],
    "MEDIUM": [
        r"test\.php$", r"info\.php$", r"phpinfo\.php$", r"README", r"CHANGELOG",
        r"/logs/", r"\.log$", r"wp-config\.php$"
    ]
}

# Dangerous/Interesting ports for Nmap
_RISKY_PORTS = {
    "MEDIUM": ["21", "23", "3389", "5900", "5901", "161", "162", "445", "139"],
    "LOW": ["80", "443", "22", "53", "25", "110", "143", "3306", "5432"]
}

# Noise patterns to ignore in FFUF
_NOISE_PATTERNS = [
    r"\.png$", r"\.jpg$", r"\.jpeg$", r"\.gif$", r"\.css$", r"\.js$",
    r"/assets/", r"/images/", r"/fonts/", r"/favicon\.ico$"
]


def _lookup_product(text: str) -> tuple[str, str] | None:
    t = text.lower()
    for key in _PRODUCT_KEYS_LONGEST_FIRST:
        if key in t:
            return PRODUCT_MAP[key]
    return None


def _pairs_from_line(line: str, source: str) -> list[Fingerprint]:
    """Find every '<Product>/<Version>' or '<Product> <Version>' in one line."""
    out: list[Fingerprint] = []
    seen: set[tuple[str, str, str]] = set()

    # Path extraction for all tools
    path_match = re.search(r"(/[A-Za-z0-9_\-./%]+)", line)
    path = path_match.group(1) if path_match else None

    # 1) "Product/Version" form (most common in HTTP Server header)
    for m in re.finditer(r"([A-Za-z][\w.+ ]{1,30}?)/(\d[\w.\-]*)", line):
        prod_text, version = m.group(1).strip(), m.group(2).strip()
        cpe = _lookup_product(prod_text)
        if not cpe:
            continue
        key = (cpe[0], cpe[1], version)
        if key in seen:
            continue
        seen.add(key)
        out.append(Fingerprint(
            vendor=cpe[0], product=cpe[1], version=version,
            path=path,
            source=source, evidence=line.strip()[:300],
        ))

    # 2) "Product Version" form (e.g. "nginx 1.18.0", "Apache httpd 2.4.49",
    #    "back-end DBMS: MySQL 5.7.32")
    for prod_key in _PRODUCT_KEYS_LONGEST_FIRST:
        idx = line.lower().find(prod_key)
        if idx < 0:
            continue
        tail = line[idx + len(prod_key) : idx + len(prod_key) + 40]
        m = _VERSION_RE.search(tail)
        if not m:
            continue
        version = m.group(1)
        # Skip obvious non-versions like "200" status codes
        if version.isdigit() and len(version) <= 3:
            continue
        cpe = PRODUCT_MAP[prod_key]
        key = (cpe[0], cpe[1], version)
        if key in seen:
            continue
        seen.add(key)
        out.append(Fingerprint(
            vendor=cpe[0], product=cpe[1], version=version,
            path=path,
            source=source, evidence=line.strip()[:300],
        ))

    return out


# ---------------------------------------------------------------
# Per-tool extractors
# ---------------------------------------------------------------

def from_nmap(output: str) -> list[Fingerprint]:
    """Parse nmap -sV style output. Lines like:
       80/tcp   open  http     Apache httpd 2.4.49 ((Unix) OpenSSL/1.1.1k PHP/7.4.3)
    """
    fps: list[Fingerprint] = []
    for line in output.splitlines():
        if "/tcp" in line and "open" in line:
            # 1. Extract software fingerprints
            fps.extend(_pairs_from_line(line, source="nmap"))

            # 2. Extract port details for smart classification
            m = re.search(r"(\d+)/tcp\s+open\s+(\S+)", line)
            if m:
                port_num = m.group(1)
                service_name = m.group(2)

                # Determine smart severity for the port
                sev = "INFO"
                for s, ports in _RISKY_PORTS.items():
                    if port_num in ports:
                        sev = s
                        break

                fps.append(Fingerprint(
                    vendor="generic", product=f"port-{port_num}/tcp",
                    version=service_name, source="nmap",
                    evidence=line.strip()[:300],
                    suggested_severity=sev
                ))
        elif "http-server-header" in line.lower():
            fps.extend(_pairs_from_line(line, source="nmap"))
    return _dedup(fps)


def from_nikto(output: str) -> list[Fingerprint]:
    """Parse nikto output. Header lines and finding lines.
       + Server: Apache/2.4.49 (Unix) OpenSSL/1.1.1k PHP/7.4.3
       + X-Powered-By: PHP/7.4.3
       + Apache/2.4.49 appears to be outdated...
    """
    fps: list[Fingerprint] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        # Skip lines that are pure metadata (start time, scan terminated, etc.)
        low = line.lower()
        if any(s in low for s in (
            "+ start time", "+ end time", "+ scan terminated",
            "+ host:", "+ root page", "+ no cgi",
        )):
            continue

        # 1. Standard software extraction
        extracted = _pairs_from_line(line, source="nikto")
        fps.extend(extracted)

        # 2. Smart Nikto Finding Extraction
        # Look for security issues reported with "+ "
        if line.startswith("+ ") and not extracted:
            sev = "MEDIUM"
            if "vulnerable" in low or "outdated" in low or "critical" in low:
                sev = "HIGH"

            # Extract path if any
            path_match = re.search(r"(/[A-Za-z0-9_\-./%]+)", line)
            path = path_match.group(1) if path_match else None

            fps.append(Fingerprint(
                vendor="generic", product="nikto-finding",
                version="issue", source="nikto",
                evidence=line.strip()[:300],
                path=path,
                suggested_severity=sev
            ))

    return _dedup(fps)


def from_sqlmap(output: str) -> list[Fingerprint]:
    """Parse sqlmap text output. Useful lines:
       back-end DBMS: MySQL 5.7.32
       web application technology: Apache 2.4.49, PHP 7.4.3
    """
    fps: list[Fingerprint] = []
    for line in output.splitlines():
        low = line.lower()
        # 1. Standard software extraction
        if "back-end dbms" in low or "web application technology" in low:
            fps.extend(_pairs_from_line(line, source="sqlmap"))

        # 2. Smart SQLMap Injection Extraction
        # Look for "Parameter: <name> (<type>)" or confirmed vulnerabilities
        if "parameter:" in low and "(" in line:
            m = re.search(r"parameter:\s+([^\s(]+)\s+\(([^)]+)\)", line, re.I)
            if m:
                fps.append(Fingerprint(
                    vendor="generic", product="sql-injection",
                    version=f"{m.group(1)} ({m.group(2)})",
                    source="sqlmap",
                    evidence=line.strip()[:300],
                    suggested_severity="CRITICAL"
                ))
    return _dedup(fps)


def from_ffuf(output: str) -> list[Fingerprint]:
    """ffuf is mostly path discovery. We extract software banners if present,
    but we also extract the discovered paths as generic findings.
    """
    fps: list[Fingerprint] = []
    for line in output.splitlines():
        if "server:" in line.lower():
            fps.extend(_pairs_from_line(line, source="ffuf"))

        # Extract discovered paths (e.g. "[Status: 200, Size: 123, Words: 456, Lines: 789] | /admin")
        if "|" in line and "Status:" in line:
            parts = line.split("|", 1)
            if len(parts) > 1:
                path = parts[1].strip()

                # Check for noise
                if any(re.search(p, path, re.I) for p in _NOISE_PATTERNS):
                    continue

                # Smart Severity Logic
                sev = "INFO"
                for s, patterns in _SENSITIVE_PATTERNS.items():
                    if any(re.search(p, path, re.I) for p in patterns):
                        sev = s
                        break

                fps.append(Fingerprint(
                    vendor="generic", product="discovered-path",
                    version=path, source="ffuf",
                    evidence=line.strip()[:300],
                    path=path,
                    suggested_severity=sev
                ))
    return _dedup(fps)


# ---------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------

_DISPATCH = {
    "NMAP":   from_nmap,
    "NIKTO":  from_nikto,
    "SQLMAP": from_sqlmap,
    "FFUF":   from_ffuf,
}


def extract(tool: str, raw_output: str) -> list[Fingerprint]:
    fn = _DISPATCH.get((tool or "").upper())
    if not fn:
        return []
    return fn(raw_output or "")


def _dedup(fps: Iterable[Fingerprint]) -> list[Fingerprint]:
    seen: set[tuple[str, str, str | None]] = set()
    out: list[Fingerprint] = []
    for fp in fps:
        key = (fp.vendor.lower(), fp.product.lower(), (fp.version or "").lower())
        if key in seen:
            continue
        seen.add(key)
        out.append(fp)
    return out


# ---------------------------------------------------------------
# CLI for quick sanity checks
# ---------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    import json
    import sys

    p = argparse.ArgumentParser(description="Extract fingerprints from scan output.")
    p.add_argument("--tool", required=True, choices=list(_DISPATCH))
    p.add_argument("--file", help="path to raw scan output (default: stdin)")
    args = p.parse_args()

    raw = open(args.file).read() if args.file else sys.stdin.read()
    fps = extract(args.tool, raw)
    print(json.dumps([fp.__dict__ for fp in fps], indent=2))
    print(f"\n[{args.tool}] extracted {len(fps)} fingerprints", file=sys.stderr)

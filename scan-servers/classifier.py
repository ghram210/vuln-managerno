"""
classifier.py
=============

Smart Classification engine for web scan findings.
Assigns severity levels (CRITICAL, HIGH, MEDIUM, LOW, INFO) to findings
based on tool-specific patterns, keywords, and risk logic.
"""

import re

def classify(tool: str, evidence: str, path: str = None) -> str:
    """
    Assign a severity level based on tool output and metadata.
    """
    tool = (tool or "").upper()
    evidence = (evidence or "").lower()
    path = (path or "").lower()

    if tool == "FFUF":
        # Critical paths
        if any(x in path for x in [".env", ".git", ".svn", ".htpasswd", "wp-config", "settings.py", "web.config"]):
            return "CRITICAL"
        # High impact configs/backups
        if any(x in path for x in ["config.php", "database.php", "db.php", "backup", ".sql", ".db", ".bak", ".old", ".zip", ".tar"]):
            return "CRITICAL"
        # Admin panels
        if any(x in path for x in ["admin", "administrator", "wp-admin", "cpanel", "phpmyadmin"]):
            return "HIGH"
        # General discoveries
        if "info.php" in path or "phpinfo.php" in path:
            return "HIGH"
        # Log files
        if ".log" in path:
            return "MEDIUM"
        return "LOW"

    if tool == "NMAP":
        # Extract port if possible
        # Example: "80/tcp open http"
        port_match = re.search(r"(\d+)/tcp", evidence)
        if port_match:
            port = int(port_match.group(1))
            # Critical/High risk ports (often unauthenticated or highly sensitive)
            if port in [445, 3389, 23, 139, 137, 135, 5900, 5901]: # SMB, RDP, Telnet, NetBIOS, RPC, VNC
                return "CRITICAL"
            if port in [21, 22, 25, 110, 143, 3306, 5432, 1521, 27017, 6379]: # FTP, SSH, SMTP, POP3, IMAP, DBs
                return "HIGH"
            # Common web/management ports
            if port in [80, 443, 8080, 8443, 8000, 8888, 9000, 9090, 10000]:
                return "MEDIUM"
        return "LOW"

    if tool == "SQLMAP":
        # Confirmed injections
        if "is vulnerable" in evidence or "parameter:" in evidence:
            return "CRITICAL"
        # Heuristic hints
        if "might be injectable" in evidence or "heuristic" in evidence:
            return "HIGH"
        return "INFO"

    if tool == "NIKTO":
        # Informational findings for security headers and other noise.
        # User requested keeping these as INFO.
        info_keywords = [
            "suggested security header",
            "header missing",
            "referrer-policy",
            "content-security-policy",
            "strict-transport-security",
            "x-content-type-options",
            "permissions-policy",
            "x-frame-options",
            "x-xss-protection",
            "cookie", "header", "allowed methods",
            "anti-clickjacking", "not found", "icon",
        ]
        if any(kw in evidence for kw in info_keywords):
            return "INFO"
        
        # Real vulnerabilities
        if any(kw in evidence for kw in ["vulnerable", "vulnerability", "exploit", "rce", "sqli", "os command", "overflow"]):
            return "HIGH"
        
        # Exposed files/folders
        if any(kw in evidence for kw in ["found", "exposed", "directory index", "sensitive"]):
            return "MEDIUM"

        return "LOW"

    # Default fallback
    if any(kw in evidence for kw in ["critical", "fatal", "emergency"]):
        return "CRITICAL"
    if any(kw in evidence for kw in ["error", "warning", "fail"]):
        return "MEDIUM"
        
    return "INFO"

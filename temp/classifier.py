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
        if any(x in path for x in [".env", ".git", ".svn", ".htpasswd"]):
            return "CRITICAL"
        # High impact configs/backups
        if any(x in path for x in ["config.php", "database.php", "db.php", "backup", ".sql", ".db"]):
            return "CRITICAL"
        # Admin panels
        if any(x in path for x in ["admin", "administrator", "wp-admin", "cpanel"]):
            return "HIGH"
        # General discoveries
        if "info.php" in path or "phpinfo.php" in path:
            return "HIGH"
        return "MEDIUM"

    if tool == "NMAP":
        # Extract port if possible
        # Example: "80/tcp open http"
        port_match = re.search(r"(\d+)/tcp", evidence)
        if port_match:
            port = int(port_match.group(1))
            if port in [21, 445, 3389, 22, 23, 139]: # FTP, SMB, RDP, SSH, Telnet, NetBIOS
                return "HIGH"
            if port in [80, 443, 8080, 8443]:
                return "MEDIUM"
        return "INFO"

    if tool == "SQLMAP":
        # Confirmed injections
        if "is vulnerable" in evidence or "parameter:" in evidence:
            return "CRITICAL"
        # Heuristic hints
        if "might be injectable" in evidence or "heuristic" in evidence:
            return "HIGH"
        return "INFO"

    if tool == "NIKTO":
        # Downgrade informational noise
        info_keywords = [
            "the anti-clickjacking x-frame-options header is not present",
            "the x-xss-protection header is not defined",
            "the x-content-type-options header is not set",
            "header missing", "suggested security header",
            "cookie", "header", "allowed methods",
        ]
        if any(kw in evidence for kw in info_keywords):
            return "INFO"
        
        # Real vulnerabilities
        if any(kw in evidence for kw in ["vulnerable", "vulnerability", "exploit", "rce", "sqli"]):
            return "HIGH"
        
        return "MEDIUM"

    # Default fallback
    if any(kw in evidence for kw in ["critical", "fatal", "emergency"]):
        return "CRITICAL"
    if any(kw in evidence for kw in ["error", "warning", "fail"]):
        return "MEDIUM"
        
    return "INFO"

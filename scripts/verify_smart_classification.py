import asyncio
import json
from pathlib import Path
import sys
import os

# Add scan-servers to path
sys.path.append(os.path.join(os.getcwd(), "scan-servers"))

import fingerprints
from matcher import MatchResult, Fingerprint
from supabase_push import build_payload, severity_counts

def test_ffuf_classification():
    print("\n--- Testing FFUF Smart Classification ---")
    ffuf_output = """
[Status: 200, Size: 123, Words: 456, Lines: 789] | /admin
[Status: 200, Size: 123, Words: 456, Lines: 789] | /.env
[Status: 200, Size: 123, Words: 456, Lines: 789] | /logo.png
[Status: 200, Size: 123, Words: 456, Lines: 789] | /test.php
[Status: 200, Size: 123, Words: 456, Lines: 789] | /about
    """
    fps = fingerprints.from_ffuf(ffuf_output)

    # Expected: .env (CRITICAL), /admin (HIGH), test.php (MEDIUM), /about (INFO), logo.png (IGNORED)
    for fp in fps:
        print(f"Path: {fp.version:<15} Severity: {fp.suggested_severity}")

    results = [MatchResult(fingerprint=fp, cves=[]) for fp in fps]
    payload = build_payload("test-scan", "FFUF", "http://test.com", results)
    counts = severity_counts(payload)
    print(f"Final Counts: {counts}")

def test_nmap_classification():
    print("\n--- Testing Nmap Smart Classification ---")
    nmap_output = """
21/tcp   open  ftp
80/tcp   open  http
3389/tcp open  ms-wbt-server
    """
    fps = fingerprints.from_nmap(nmap_output)

    # Expected: 21 (MEDIUM), 3389 (MEDIUM), 80 (LOW)
    for fp in fps:
        print(f"Port: {fp.product:<15} Severity: {fp.suggested_severity}")

    results = [MatchResult(fingerprint=fp, cves=[]) for fp in fps]
    payload = build_payload("test-scan", "NMAP", "http://test.com", results)
    counts = severity_counts(payload)
    print(f"Final Counts: {counts}")

def test_sqlmap_classification():
    print("\n--- Testing SQLMap Smart Classification ---")
    sqlmap_output = """
[INFO] the back-end DBMS is MySQL
Parameter: id (GET)
    Type: boolean-based blind
    Title: MySQL >= 5.0.12 AND boolean-based blind - WHERE, HAVING, GROUP BY or ORDER BY clause
    Payload: id=1 AND (SELECT 8132 FROM(SELECT COUNT(*),CONCAT(0x71787a7a71,(SELECT (ELT(8132=8132,1))),0x71707a7871,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)
    """
    fps = fingerprints.from_sqlmap(sqlmap_output)

    # Expected: id (GET) (CRITICAL)
    for fp in fps:
        print(f"Injection: {fp.version:<15} Severity: {fp.suggested_severity}")

    results = [MatchResult(fingerprint=fp, cves=[]) for fp in fps]
    payload = build_payload("test-scan", "SQLMAP", "http://test.com", results)
    counts = severity_counts(payload)
    print(f"Final Counts: {counts}")

def test_nikto_classification():
    print("\n--- Testing Nikto Smart Classification ---")
    nikto_output = """
+ Server: Apache/2.4.41 (Ubuntu)
+ /phpinfo.php: Contains PHP configuration information.
+ /admin/: Admin panel found.
+ The anti-clickjacking X-Frame-Options header is not present.
    """
    fps = fingerprints.from_nikto(nikto_output)

    for fp in fps:
        print(f"Finding: {fp.product:<15} Severity: {fp.suggested_severity or 'NVD'}")

    results = [MatchResult(fingerprint=fp, cves=[]) for fp in fps]
    payload = build_payload("test-scan", "NIKTO", "http://test.com", results)
    counts = severity_counts(payload)
    print(f"Final Counts: {counts}")

if __name__ == "__main__":
    test_ffuf_classification()
    test_nmap_classification()
    test_sqlmap_classification()
    test_nikto_classification()

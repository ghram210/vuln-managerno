
import sys
import os
sys.path.append(os.path.abspath("scan-servers"))

import classifier
import fingerprints
import supabase_push
from matcher import MatchResult, Fingerprint, CVEHit

def test_ffuf_classification():
    print("Testing FFUF classification...")
    output = "  /.env  [HTTP 200 | Size:123 Words:45]\n  /admin  [HTTP 200 | Size:456 Words:78]\n  /index.php  [HTTP 200 | Size:789 Words:12]"
    fps = fingerprints.extract("FFUF", output)

    # Filter only intelligence findings for this check
    intel_fps = [fp for fp in fps if fp.vendor == "Intelligence"]

    for fp in intel_fps:
        sev = classifier.classify("FFUF", fp.evidence, fp.path)
        print(f"Path: {fp.path} -> Severity: {sev}")
        if ".env" in fp.path:
            assert sev == "CRITICAL"
        elif "admin" in fp.path:
            assert sev == "HIGH"

def test_nmap_classification():
    print("\nTesting Nmap classification...")
    output = "80/tcp open http\n445/tcp open microsoft-ds"
    fps = fingerprints.extract("NMAP", output)
    intel_fps = [fp for fp in fps if fp.vendor == "Intelligence"]

    for fp in intel_fps:
        sev = classifier.classify("NMAP", fp.evidence)
        print(f"Evidence: {fp.evidence} -> Severity: {sev}")
        if "80/tcp" in fp.evidence:
            assert sev == "MEDIUM"
        elif "445/tcp" in fp.evidence:
            assert sev == "HIGH"

def test_sqlmap_classification():
    print("\nTesting SQLMap classification...")
    output = "Parameter: id (GET) is vulnerable"
    fps = fingerprints.extract("SQLMAP", output)
    intel_fps = [fp for fp in fps if fp.vendor == "Intelligence"]

    for fp in intel_fps:
        sev = classifier.classify("SQLMAP", fp.evidence)
        print(f"Evidence: {fp.evidence} -> Severity: {sev}")
        assert sev == "CRITICAL"

def test_nikto_classification():
    print("\nTesting Nikto classification...")
    output = "+ The anti-clickjacking X-Frame-Options header is not present.\n+ OSVDB-3092: /test.php: This might be interesting."
    fps = fingerprints.extract("NIKTO", output)
    intel_fps = [fp for fp in fps if fp.vendor == "Intelligence"]

    for fp in intel_fps:
        sev = classifier.classify("NIKTO", fp.evidence)
        print(f"Evidence: {fp.evidence} -> Severity: {sev}")
        if "clickjacking" in fp.evidence.lower():
            assert sev == "LOW"

def test_formatted_nikto_parsing():
    print("\nTesting formatted Nikto parsing (database format)...")
    output = "NIKTO [NORMAL MODE] — Target: testfire.net\nUnique findings: 1\n============================================================\nFindings (1 unique):\n----------------------------------------\n  The anti-clickjacking X-Frame-Options header is not present."
    fps = fingerprints.extract("NIKTO", output)
    assert len(fps) > 0
    print(f"Extracted {len(fps)} findings from formatted output")

def test_hybrid_priority():
    print("\nTesting Hybrid System (NVD Priority)...")
    fp = Fingerprint(vendor="apache", product="http_server", version="2.4.49", source="nmap", evidence="80/tcp open http Apache 2.4.49")

    # Case 1: No CVEs -> Smart Intelligence (MEDIUM for port 80)
    res1 = MatchResult(fingerprint=fp, cves=[])
    payload1 = supabase_push.build_payload("scan-1", "NMAP", "target-1", [res1])
    finding1 = payload1["scan_findings"][0]
    print(f"No CVEs -> Severity: {finding1['severity']} (Source: {finding1['metadata']['classification_source']})")
    assert finding1['severity'] == "medium"
    assert finding1['metadata']['classification_source'] == "Smart Intelligence"

    # Case 2: With CVE (e.g. CRITICAL) -> NVD Priority
    cve = CVEHit(cve_id="CVE-2021-41773", description="Path traversal", cvss_score=9.8, cvss_severity="CRITICAL", cvss_vector="", cvss_version="", published_date="", last_modified="")
    res2 = MatchResult(fingerprint=fp, cves=[cve])
    payload2 = supabase_push.build_payload("scan-1", "NMAP", "target-1", [res2])
    finding2 = payload2["scan_findings"][0]
    print(f"With CVE -> Severity: {finding2['severity']} (Source: {finding2['metadata']['classification_source']})")
    assert finding2['severity'] == "critical"
    assert finding2['metadata']['classification_source'] == "NVD (CVE Match)"

if __name__ == "__main__":
    try:
        test_ffuf_classification()
        test_nmap_classification()
        test_sqlmap_classification()
        test_nikto_classification()
        test_formatted_nikto_parsing()
        test_hybrid_priority()
        print("\nALL TESTS PASSED!")
    except AssertionError as e:
        print(f"\nTEST FAILED!")
        sys.exit(1)
    except Exception as e:
        print(f"\nAN ERROR OCCURRED: {e}")
        sys.exit(1)

import asyncio
import json
from pathlib import Path
import sys
import os

# Add scan-servers to path
sys.path.append(os.path.join(os.getcwd(), "scan-servers"))

import fingerprints
from matcher import MatchResult, Fingerprint, CVEHit
from supabase_push import build_payload, severity_counts

def test_hybrid_classification():
    print("\n--- Testing Hybrid (NVD + Smart) Classification ---")

    # 1. Mock NVD Match (Nikto finding a software version)
    fp_nvd = Fingerprint(vendor="apache", product="http_server", version="2.4.49", source="nikto")
    cve_hit = CVEHit(cve_id="CVE-2021-41773", description="Path traversal", cvss_score=7.5, cvss_severity="HIGH", cvss_vector="...", cvss_version="3.1", published_date="...", last_modified="...")
    res_nvd = MatchResult(fingerprint=fp_nvd, cves=[cve_hit])

    # 2. Mock Smart Finding (Nikto finding a config issue)
    fp_smart = Fingerprint(vendor="generic", product="nikto-finding", version="issue", source="nikto", evidence="+ The anti-clickjacking header is not present.", suggested_severity="LOW")
    res_smart = MatchResult(fingerprint=fp_smart, cves=[])

    results = [res_nvd, res_smart]
    payload = build_payload("test-scan", "NIKTO", "http://test.com", results)

    for f in payload["scan_findings"]:
        source = f["metadata"].get("classification_source")
        print(f"Title: {f['title']:<40} Source: {source:<20}")

    counts = severity_counts(payload)
    print(f"Final Counts: {counts}")
    assert counts["high_count"] == 1
    assert counts["low_count"] == 1

def test_sqlmap_critical():
    print("\n--- Testing SQLMap Critical Classification ---")
    sqlmap_output = "Parameter: id (GET)\n    Type: boolean-based blind"
    fps = fingerprints.from_sqlmap(sqlmap_output)
    results = [MatchResult(fingerprint=fp, cves=[]) for fp in fps]
    payload = build_payload("test-scan", "SQLMAP", "http://test.com", results)

    for f in payload["scan_findings"]:
        print(f"Title: {f['title']:<40} Source: {f['metadata'].get('classification_source')}")

    counts = severity_counts(payload)
    print(f"Final Counts: {counts}")
    assert counts["critical_count"] == 1

if __name__ == "__main__":
    test_hybrid_classification()
    test_sqlmap_critical()
    print("\n✓ ALL VERIFICATIONS PASSED")

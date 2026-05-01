-- =============================================================
-- Dashboard Updates: New analytics views
-- =============================================================

BEGIN;

-- -------------------------------------------------------------
-- 1. View: Top 5 At-Risk Assets (Targets with most Critical/High findings)
-- -------------------------------------------------------------
-- Using DISTINCT f.id to avoid overcounting if a finding has multiple CVEs
CREATE OR REPLACE VIEW public.vuln_top_assets AS
SELECT
  md5(f.target)::uuid as id,
  f.target as label,
  COUNT(DISTINCT f.id)::int as value,
  'hsl(0 72% 55%)' as color,
  1 as sort_order
FROM public.scan_findings f
LEFT JOIN public.finding_cves fc ON fc.finding_id = f.id
LEFT JOIN public.cve_catalog c ON c.cve_id = fc.cve_id
WHERE f.status = 'open'
  AND UPPER(COALESCE(c.cvss_v3_severity, 'MEDIUM')) IN ('CRITICAL', 'HIGH')
GROUP BY f.target
ORDER BY value DESC
LIMIT 5;

-- -------------------------------------------------------------
-- 2. View: Vulnerabilities by Discovery Tool
-- -------------------------------------------------------------
CREATE OR REPLACE VIEW public.vuln_by_tool AS
SELECT
  md5(f.tool)::uuid as id,
  f.tool as label,
  COUNT(f.id)::int as value,
  CASE
    WHEN f.tool = 'NMAP' THEN 'hsl(210 70% 55%)'
    WHEN f.tool = 'NIKTO' THEN 'hsl(280 65% 60%)'
    WHEN f.tool = 'SQLMAP' THEN 'hsl(340 75% 55%)'
    WHEN f.tool = 'FFUF' THEN 'hsl(160 60% 45%)'
    ELSE 'hsl(210 15% 55%)'
  END as color,
  1 as sort_order
FROM public.scan_findings f
WHERE f.status = 'open'
GROUP BY f.tool
ORDER BY value DESC;

-- -------------------------------------------------------------
-- 3. Grants
-- -------------------------------------------------------------
GRANT SELECT ON
  public.vuln_top_assets,
  public.vuln_by_tool
TO anon, authenticated;

COMMIT;

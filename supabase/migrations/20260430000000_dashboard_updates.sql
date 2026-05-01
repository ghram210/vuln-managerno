-- =============================================================
-- Dashboard Updates: Asset-level filtering and bug fixes
-- =============================================================

BEGIN;

-- -------------------------------------------------------------
-- 1. Safely drop views to be updated
-- -------------------------------------------------------------
DROP VIEW IF EXISTS public.vuln_top_assets CASCADE;
DROP VIEW IF EXISTS public.vuln_by_tool CASCADE;
DROP VIEW IF EXISTS public.vuln_rating_overview_filtered CASCADE;
DROP VIEW IF EXISTS public.remediation_open_filtered CASCADE;
DROP VIEW IF EXISTS public.remediation_closed CASCADE;

-- -------------------------------------------------------------
-- 2. View: Vulnerability Rating Overview (Supports filtering by target)
-- -------------------------------------------------------------
CREATE OR REPLACE VIEW public.vuln_rating_overview_filtered AS
WITH findings_with_sev AS (
  SELECT
    f.id,
    f.target,
    UPPER(COALESCE(c.cvss_v3_severity, 'MEDIUM')) as severity
  FROM public.scan_findings f
  LEFT JOIN public.finding_cves fc ON fc.finding_id = f.id
  LEFT JOIN public.cve_catalog c ON c.cve_id = fc.cve_id
  WHERE f.status = 'open'
),
deduped_findings AS (
  SELECT
    id,
    target,
    CASE
      WHEN bool_or(severity = 'CRITICAL') THEN 'Critical'
      WHEN bool_or(severity = 'HIGH')     THEN 'High'
      WHEN bool_or(severity = 'MEDIUM')   THEN 'Medium'
      ELSE 'Low'
    END as rating
  FROM findings_with_sev
  GROUP BY id, target
)
SELECT
  md5(COALESCE(target, 'all') || rating)::uuid as id,
  target,
  rating as label,
  COUNT(*)::int as value,
  CASE
    WHEN rating = 'Critical' THEN 'hsl(0 84% 60%)'
    WHEN rating = 'High'     THEN 'hsl(24 95% 53%)'
    WHEN rating = 'Medium'   THEN 'hsl(45 93% 47%)'
    ELSE 'hsl(142 71% 45%)'
  END as color,
  CASE
    WHEN rating = 'Critical' THEN 1
    WHEN rating = 'High'     THEN 2
    WHEN rating = 'Medium'   THEN 3
    ELSE 4
  END as sort_order
FROM deduped_findings
GROUP BY target, rating;

-- -------------------------------------------------------------
-- 3. View: Top 5 At-Risk Assets
-- -------------------------------------------------------------
CREATE OR REPLACE VIEW public.vuln_top_assets AS
SELECT
  md5(f.target)::uuid as id,
  f.target as label,
  COUNT(DISTINCT f.id)::int as value,
  'hsl(0 84% 60%)' as color,
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
-- 4. View: Vulnerabilities by Discovery Tool (Supports filtering by target)
-- -------------------------------------------------------------
CREATE OR REPLACE VIEW public.vuln_by_tool AS
SELECT
  md5(COALESCE(f.target, 'all') || f.tool)::uuid as id,
  f.target,
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
GROUP BY f.target, f.tool;

-- -------------------------------------------------------------
-- 5. View: Remediation Compliance (Open) - Supports filtering by target
-- -------------------------------------------------------------
CREATE OR REPLACE VIEW public.remediation_open_filtered AS
WITH sev_levels(rating, color, sort_order, allowed_days) AS (
  VALUES
    ('Critical', 'hsl(0 84% 60%)', 1, 7),
    ('High',     'hsl(24 95% 53%)',  2, 30),
    ('Medium',   'hsl(45 93% 47%)',  3, 90),
    ('Low',      'hsl(142 71% 45%)', 4, 180)
),
deduped_findings AS (
  SELECT
    f.id,
    f.target,
    f.created_at,
    CASE
      WHEN bool_or(UPPER(COALESCE(c.cvss_v3_severity, 'MEDIUM')) = 'CRITICAL') THEN 'Critical'
      WHEN bool_or(UPPER(COALESCE(c.cvss_v3_severity, 'MEDIUM')) = 'HIGH')     THEN 'High'
      WHEN bool_or(UPPER(COALESCE(c.cvss_v3_severity, 'MEDIUM')) = 'MEDIUM')   THEN 'Medium'
      ELSE 'Low'
    END as sev
  FROM public.scan_findings f
  LEFT JOIN public.finding_cves fc ON fc.finding_id = f.id
  LEFT JOIN public.cve_catalog c ON c.cve_id = fc.cve_id
  WHERE f.status = 'open'
  GROUP BY f.id, f.target, f.created_at
)
SELECT
  md5(targets.target || sl.rating)::uuid AS id,
  targets.target,
  sl.rating,
  sl.color,
  'last_30_days' AS time_frame,
  COALESCE(ROUND(COUNT(f.id) FILTER (WHERE (now() - f.created_at) <= (sl.allowed_days * interval '1 day'))::float / NULLIF(COUNT(f.id), 0) * 100), 100)::int AS in_compliance,
  COALESCE(100 - ROUND(COUNT(f.id) FILTER (WHERE (now() - f.created_at) <= (sl.allowed_days * interval '1 day'))::float / NULLIF(COUNT(f.id), 0) * 100), 0)::int AS not_in_compliance,
  sl.sort_order
FROM sev_levels sl
CROSS JOIN (SELECT DISTINCT target FROM public.scan_findings) targets
LEFT JOIN deduped_findings f ON f.sev = sl.rating AND f.target = targets.target
GROUP BY targets.target, sl.rating, sl.color, sl.sort_order;

-- -------------------------------------------------------------
-- 6. Grants
-- -------------------------------------------------------------
GRANT SELECT ON
  public.vuln_top_assets,
  public.vuln_by_tool,
  public.vuln_rating_overview_filtered,
  public.remediation_open_filtered
TO anon, authenticated;

COMMIT;

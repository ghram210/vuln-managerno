-- =============================================================
-- Dashboard Updates: Bug fixes and new analytics views
-- =============================================================

BEGIN;

-- -------------------------------------------------------------
-- 1. Fix: Vulnerability Rating Overview (Overcounting bug)
-- -------------------------------------------------------------
CREATE OR REPLACE VIEW public.vuln_rating_overview AS
WITH findings_with_sev AS (
  SELECT
    f.id,
    UPPER(COALESCE(c.cvss_v3_severity, 'MEDIUM')) as severity
  FROM public.scan_findings f
  LEFT JOIN public.finding_cves fc ON fc.finding_id = f.id
  LEFT JOIN public.cve_catalog c ON c.cve_id = fc.cve_id
  WHERE f.status = 'open'
),
deduped_findings AS (
  -- Ensure each finding is only counted once, taking the highest severity if multiple CVEs exist
  SELECT
    id,
    CASE
      WHEN bool_or(severity = 'CRITICAL') THEN 'Critical'
      WHEN bool_or(severity = 'HIGH')     THEN 'High'
      WHEN bool_or(severity = 'MEDIUM')   THEN 'Medium'
      ELSE 'Low'
    END as rating
  FROM findings_with_sev
  GROUP BY id
),
total AS (SELECT COUNT(*)::float as cnt FROM deduped_findings),
counts AS (
  SELECT rating, COUNT(*) as val
  FROM deduped_findings
  GROUP BY rating
)
SELECT
  md5(r.label)::uuid as id,
  r.label,
  COALESCE(c.val, 0)::int as value,
  CASE
    WHEN (SELECT cnt FROM total) = 0 THEN 0
    ELSE ROUND((COALESCE(c.val, 0)::float / (SELECT cnt FROM total)) * 100)::int
  END as percentage,
  r.color,
  r.sort_order
FROM (
  VALUES
    ('Critical', 'hsl(0 72% 55%)', 1),
    ('High', 'hsl(25 95% 55%)', 2),
    ('Medium', 'hsl(210 70% 55%)', 3),
    ('Low', 'hsl(150 70% 50%)', 4)
) r(label, color, sort_order)
LEFT JOIN counts c ON c.rating = r.label
ORDER BY sort_order;

-- -------------------------------------------------------------
-- 2. View: Top 5 At-Risk Assets (Targets with most Critical/High findings)
-- -------------------------------------------------------------
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
-- 3. View: Vulnerabilities by Discovery Tool
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
-- 4. Fix: Remediation Compliance (Open) - Overcounting bug
-- -------------------------------------------------------------
CREATE OR REPLACE VIEW public.remediation_open AS
WITH sev_levels(rating, color, sort_order, allowed_days) AS (
  VALUES
    ('Critical', 'hsl(355 70% 62%)', 1, 7),
    ('High',     'hsl(25 78% 62%)',  2, 30),
    ('Medium',   'hsl(45 75% 62%)',  3, 90),
    ('Low',      'hsl(155 50% 55%)', 4, 180)
),
deduped_findings AS (
  SELECT
    f.id,
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
  GROUP BY f.id, f.created_at
),
findings_stats AS (
  SELECT
    sl.rating,
    COUNT(f.id) AS total_count,
    COUNT(f.id) FILTER (WHERE (now() - f.created_at) <= (sl.allowed_days * interval '1 day')) AS in_comp_count
  FROM sev_levels sl
  LEFT JOIN deduped_findings f ON f.sev = sl.rating
  GROUP BY sl.rating
)
SELECT
  md5(sl.rating)::uuid AS id,
  sl.rating,
  sl.color,
  'last_30_days' AS time_frame,
  CASE WHEN fs.total_count = 0 THEN 100 ELSE ROUND((fs.in_comp_count::float / fs.total_count::float) * 100)::int END AS in_compliance,
  CASE WHEN fs.total_count = 0 THEN 0   ELSE 100 - ROUND((fs.in_comp_count::float / fs.total_count::float) * 100)::int END AS not_in_compliance,
  sl.sort_order
FROM sev_levels sl
LEFT JOIN findings_stats fs ON fs.rating = sl.rating;

-- -------------------------------------------------------------
-- 5. Fix: Remediation Compliance (Closed) - Overcounting bug
-- -------------------------------------------------------------
CREATE OR REPLACE VIEW public.remediation_closed AS
WITH sev_levels(rating, color, sort_order, allowed_days) AS (
  VALUES
    ('Critical', 'hsl(155 50% 55%)', 1, 7),
    ('High',     'hsl(155 50% 55%)', 2, 30),
    ('Medium',   'hsl(155 50% 55%)', 3, 90),
    ('Low',      'hsl(155 50% 55%)', 4, 180)
),
deduped_findings AS (
  SELECT
    f.id,
    f.created_at,
    sr.completed_at,
    CASE
      WHEN bool_or(UPPER(COALESCE(c.cvss_v3_severity, 'MEDIUM')) = 'CRITICAL') THEN 'Critical'
      WHEN bool_or(UPPER(COALESCE(c.cvss_v3_severity, 'MEDIUM')) = 'HIGH')     THEN 'High'
      WHEN bool_or(UPPER(COALESCE(c.cvss_v3_severity, 'MEDIUM')) = 'MEDIUM')   THEN 'Medium'
      ELSE 'Low'
    END as sev
  FROM public.scan_findings f
  LEFT JOIN public.finding_cves fc ON fc.finding_id = f.id
  LEFT JOIN public.cve_catalog c ON c.cve_id = fc.cve_id
  LEFT JOIN public.scan_results sr ON sr.id = f.scan_id
  WHERE f.status IN ('fixed', 'resolved', 'closed')
  GROUP BY f.id, f.created_at, sr.completed_at
),
findings_stats AS (
  SELECT
    sl.rating,
    COUNT(f.id) AS total_count,
    COUNT(f.id) FILTER (WHERE (f.completed_at - f.created_at) <= (sl.allowed_days * interval '1 day')) AS in_comp_count
  FROM sev_levels sl
  LEFT JOIN deduped_findings f ON f.sev = sl.rating
  GROUP BY sl.rating
)
SELECT
  md5(sl.rating || 'closed')::uuid AS id,
  sl.rating,
  sl.color,
  'last_30_days' AS time_frame,
  CASE WHEN fs.total_count = 0 THEN 100 ELSE ROUND((fs.in_comp_count::float / fs.total_count::float) * 100)::int END AS in_compliance,
  CASE WHEN fs.total_count = 0 THEN 0   ELSE 100 - ROUND((fs.in_comp_count::float / fs.total_count::float) * 100)::int END AS not_in_compliance,
  sl.sort_order
FROM sev_levels sl
LEFT JOIN findings_stats fs ON fs.rating = sl.rating;

-- -------------------------------------------------------------
-- 6. Grants
-- -------------------------------------------------------------
GRANT SELECT ON
  public.vuln_top_assets,
  public.vuln_by_tool,
  public.vuln_rating_overview,
  public.remediation_open,
  public.remediation_closed
TO anon, authenticated;

COMMIT;

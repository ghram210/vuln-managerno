-- =============================================================
-- Dashboard Complete: Final Consolidated Views with Filtering & Bug Fixes
-- =============================================================
-- This migration replaces all previous dashboard-related views.
-- It fixes the 650% overcounting bug and enables global asset filtering.
-- =============================================================

BEGIN;

-- 1. Clean up all previous versions to avoid conflicts
DROP VIEW IF EXISTS public.vuln_top_assets CASCADE;
DROP VIEW IF EXISTS public.vuln_by_tool CASCADE;
DROP VIEW IF EXISTS public.vuln_rating_overview_filtered CASCADE;
DROP VIEW IF EXISTS public.vuln_rating_overview CASCADE;
DROP VIEW IF EXISTS public.vuln_risk_score CASCADE;
DROP VIEW IF EXISTS public.vuln_daily_open CASCADE;
DROP VIEW IF EXISTS public.dash_kpi_mttr CASCADE;
DROP VIEW IF EXISTS public.dash_kpi_weaponized CASCADE;
DROP VIEW IF EXISTS public.dash_kpi_compliance CASCADE;
DROP VIEW IF EXISTS public.remediation_open_filtered CASCADE;
DROP VIEW IF EXISTS public.remediation_open CASCADE;
DROP VIEW IF EXISTS public.remediation_closed CASCADE;

-- 2. Severity Cards View (Fixes Overcounting and supports Filtering)
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

-- 3. Top 5 At-Risk Assets View
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

-- 4. Vulnerabilities by Discovery Tool View (supports Filtering)
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

-- 5. Risk Score View (supports Filtering)
CREATE OR REPLACE VIEW public.vuln_risk_score AS
WITH finding_risk AS (
  SELECT
    f.id,
    f.target,
    (SELECT COALESCE(MAX(c.cvss_v3_score), 5.0) FROM public.finding_cves fc JOIN public.cve_catalog c ON c.cve_id = fc.cve_id WHERE fc.finding_id = f.id) AS base_score,
    CASE
      WHEN EXISTS (SELECT 1 FROM public.finding_cves fc JOIN public.exploits e ON e.cve_id = fc.cve_id WHERE fc.finding_id = f.id AND e.verified IS TRUE) THEN 1.8
      WHEN EXISTS (SELECT 1 FROM public.finding_cves fc JOIN public.exploits e ON e.cve_id = fc.cve_id WHERE fc.finding_id = f.id) THEN 1.4
      ELSE 1.0
    END AS exploit_factor,
    CASE
      WHEN f.service ~* '(postgres|mysql|sql|oracle|db|mongodb|redis|auth|ldap|ad|kerberos|pax)' THEN 1.5
      ELSE 1.0
    END AS criticality_factor,
    CASE
      WHEN f.service ~* '(http|https|ssh|rdp|vnc|ftp|smtp)' THEN 1.2
      ELSE 1.0
    END AS exposure_factor
  FROM public.scan_findings f
  WHERE f.status = 'open'
),
scored_findings AS (
  SELECT
    id,
    target,
    base_score,
    (base_score * exploit_factor) - base_score AS exploit_impact,
    (base_score * exploit_factor * criticality_factor) - (base_score * exploit_factor) AS asset_impact,
    (base_score * exploit_factor * criticality_factor * exposure_factor) - (base_score * exploit_factor * criticality_factor) AS exposure_impact
  FROM finding_risk
)
SELECT
  md5(COALESCE(target, 'all') || label)::uuid AS id,
  target,
  label,
  COALESCE(ROUND(SUM(val)), 0)::int AS value,
  color,
  sort_order
FROM (
  SELECT target, 'Base CVSS' AS label, SUM(base_score) AS val, 'hsl(210 70% 55%)' AS color, 1 AS sort_order FROM scored_findings GROUP BY target
  UNION ALL
  SELECT target, 'Exploitability' AS label, SUM(exploit_impact) AS val, 'hsl(0 72% 55%)' AS color, 2 AS sort_order FROM scored_findings GROUP BY target
  UNION ALL
  SELECT target, 'Asset Criticality' AS label, SUM(asset_impact) AS val, 'hsl(270 60% 55%)' AS color, 3 AS sort_order FROM scored_findings GROUP BY target
  UNION ALL
  SELECT target, 'Exposure' AS label, SUM(exposure_impact) AS val, 'hsl(30 90% 55%)' AS color, 4 AS sort_order FROM scored_findings GROUP BY target
) sub
GROUP BY target, label, color, sort_order;

-- 6. Daily Open Trend View (supports Filtering)
CREATE OR REPLACE VIEW public.vuln_daily_open AS
WITH RECURSIVE days AS (
  SELECT (CURRENT_DATE - INTERVAL '44 days')::DATE AS day_date, 1 AS day_num
  UNION ALL
  SELECT (day_date + INTERVAL '1 day')::DATE, day_num + 1
  FROM days
  WHERE day_num < 45
),
targets AS (
  SELECT DISTINCT target FROM public.scan_findings
)
SELECT
  md5(d.day_date::text || COALESCE(t.target, 'all'))::uuid AS id,
  t.target,
  d.day_num AS day,
  COUNT(f.id)::int AS count
FROM days d
CROSS JOIN targets t
LEFT JOIN public.scan_findings f ON f.created_at::date <= d.day_date
  AND f.target = t.target
  AND (f.status = 'open' OR (f.status IN ('fixed', 'resolved', 'closed', 'false_positive') AND EXISTS (
      SELECT 1 FROM public.scan_results sr WHERE sr.id = f.scan_id AND (sr.completed_at::date > d.day_date OR sr.completed_at IS NULL)
  )))
GROUP BY d.day_date, d.day_num, t.target;

-- 7. KPI: MTTR View (supports Filtering)
CREATE OR REPLACE VIEW public.dash_kpi_mttr AS
SELECT
  md5(COALESCE(f.target, 'all'))::uuid as id,
  f.target,
  'MTTR' AS label,
  COALESCE(ROUND(AVG(EXTRACT(EPOCH FROM (sr.completed_at - f.created_at)) / 86400)), 0)::int AS value,
  'Days' AS unit,
  'hsl(190 65% 58%)' AS color
FROM public.scan_findings f
JOIN public.scan_results sr ON sr.id = f.scan_id
WHERE f.status IN ('fixed', 'resolved', 'closed', 'false_positive') AND sr.completed_at IS NOT NULL
GROUP BY f.target;

-- 8. KPI: Weaponized Risks View (supports Filtering)
CREATE OR REPLACE VIEW public.dash_kpi_weaponized AS
SELECT
  md5(COALESCE(f.target, 'all'))::uuid as id,
  f.target,
  'Weaponized' AS label,
  COUNT(DISTINCT f.id)::int AS value,
  'Risks' AS unit,
  'hsl(355 70% 62%)' AS color
FROM public.scan_findings f
WHERE f.status = 'open'
  AND EXISTS (
    SELECT 1 FROM public.finding_cves fc
    JOIN public.exploits e ON e.cve_id = fc.cve_id
    WHERE fc.finding_id = f.id AND e.verified IS TRUE
  )
GROUP BY f.target;

-- 9. KPI: SLA Compliance View (supports Filtering)
CREATE OR REPLACE VIEW public.dash_kpi_compliance AS
WITH findings_with_deadline AS (
  SELECT
    f.id,
    f.target,
    f.created_at,
    (
      SELECT COALESCE(c.cvss_v3_severity, 'MEDIUM')
      FROM public.finding_cves fc
      JOIN public.cve_catalog c ON c.cve_id = fc.cve_id
      WHERE fc.finding_id = f.id
      LIMIT 1
    ) AS sev
  FROM public.scan_findings f
  WHERE f.status = 'open'
),
deadlines AS (
  SELECT
    target,
    CASE
      WHEN UPPER(sev) = 'CRITICAL' THEN interval '7 days'
      WHEN UPPER(sev) = 'HIGH'     THEN interval '30 days'
      WHEN UPPER(sev) = 'MEDIUM'   THEN interval '90 days'
      ELSE interval '180 days'
    END AS allowed_time,
    created_at
  FROM findings_with_deadline
),
stats AS (
  SELECT
    target,
    COUNT(*) AS total_open,
    COUNT(*) FILTER (WHERE (now() - created_at) <= allowed_time) AS in_comp
  FROM deadlines
  GROUP BY target
)
SELECT
  md5(COALESCE(target, 'all'))::uuid as id,
  target,
  'Compliance' AS label,
  CASE WHEN total_open = 0 THEN 100 ELSE ROUND((in_comp::float / total_open::float) * 100)::int END AS value,
  '%' AS unit,
  'hsl(155 50% 55%)' AS color
FROM stats;

-- 10. Remediation Compliance Tables (Fixes syntax error and logic)
CREATE OR REPLACE VIEW public.remediation_open_filtered AS
WITH sev_levels(rating, color, sort_order, allowed_days) AS (
  VALUES
    ('Critical', 'hsl(0 84% 60%)', 1, 7),
    ('High',     'hsl(24 95% 53%)',  2, 30),
    ('Medium',   'hsl(45 93% 47%)',  3, 90),
    ('Low',      'hsl(142 71% 45%)', 4, 180)
),
targets AS (
  SELECT DISTINCT target FROM public.scan_findings
),
finding_info AS (
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
),
finding_compliance AS (
  SELECT
    id,
    target,
    sev,
    CASE
      WHEN sev = 'Critical' AND (now() - created_at) <= interval '7 days' THEN 1
      WHEN sev = 'High'     AND (now() - created_at) <= interval '30 days' THEN 1
      WHEN sev = 'Medium'   AND (now() - created_at) <= interval '90 days' THEN 1
      WHEN sev = 'Low'      AND (now() - created_at) <= interval '180 days' THEN 1
      ELSE 0
    END as is_in_comp
  FROM finding_info
)
SELECT
  md5(COALESCE(t.target, 'all') || sl.rating)::uuid AS id,
  t.target,
  sl.rating,
  sl.color,
  'last_30_days' AS time_frame,
  COUNT(f.id)::int as total_count,
  SUM(COALESCE(f.is_in_comp, 0))::int as in_comp_count,
  sl.sort_order
FROM sev_levels sl
CROSS JOIN targets t
LEFT JOIN finding_compliance f ON f.sev = sl.rating AND f.target = t.target
GROUP BY t.target, sl.rating, sl.color, sl.sort_order;

CREATE OR REPLACE VIEW public.remediation_closed AS
WITH sev_levels(rating, color, sort_order, allowed_days) AS (
  VALUES
    ('Critical', 'hsl(142 71% 45%)', 1, 7),
    ('High',     'hsl(142 71% 45%)', 2, 30),
    ('Medium',   'hsl(142 71% 45%)', 3, 90),
    ('Low',      'hsl(142 71% 45%)', 4, 180)
),
targets AS (
  SELECT DISTINCT target FROM public.scan_findings
),
finding_info AS (
  SELECT
    f.id,
    f.target,
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
  GROUP BY f.id, f.target, f.created_at, sr.completed_at
),
finding_compliance AS (
  SELECT
    id,
    target,
    sev,
    CASE
      WHEN sev = 'Critical' AND (completed_at - created_at) <= interval '7 days' THEN 1
      WHEN sev = 'High'     AND (completed_at - created_at) <= interval '30 days' THEN 1
      WHEN sev = 'Medium'   AND (completed_at - created_at) <= interval '90 days' THEN 1
      WHEN sev = 'Low'      AND (completed_at - created_at) <= interval '180 days' THEN 1
      ELSE 0
    END as is_in_comp
  FROM finding_info
)
SELECT
  md5(COALESCE(t.target, 'all') || sl.rating || 'closed')::uuid AS id,
  t.target,
  sl.rating,
  sl.color,
  'last_30_days' AS time_frame,
  COUNT(f.id)::int as total_count,
  SUM(COALESCE(f.is_in_comp, 0))::int as in_comp_count,
  sl.sort_order
FROM sev_levels sl
CROSS JOIN targets t
LEFT JOIN finding_compliance f ON f.sev = sl.rating AND f.target = t.target
GROUP BY t.target, sl.rating, sl.color, sl.sort_order;

-- 11. Final Grants
GRANT SELECT ON ALL TABLES IN SCHEMA public TO anon, authenticated;

COMMIT;

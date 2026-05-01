-- =============================================================
-- Dashboard Final: Comprehensive Filtering and Metric Accuracy
-- =============================================================
-- This migration consolidates all fixes for the dashboard including:
-- 1. Risk Score and Daily Trend filtering (from 20260501)
-- 2. KPI Cards (MTTR, Weaponized, Compliance)
-- 3. Remediation Tables and Overcounting fixes
-- =============================================================

BEGIN;

-- -------------------------------------------------------------
-- 1. Update vuln_risk_score to support target and normalization
-- -------------------------------------------------------------
DROP VIEW IF EXISTS public.dash_kpi_risk_total CASCADE;
DROP VIEW IF EXISTS public.vuln_risk_score CASCADE;

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

-- -------------------------------------------------------------
-- 2. Update vuln_daily_open to support target filtering
-- -------------------------------------------------------------
DROP VIEW IF EXISTS public.vuln_daily_open CASCADE;

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

-- -------------------------------------------------------------
-- 3. KPI: MTTR (Mean Time To Remediate) with target support
-- -------------------------------------------------------------
DROP VIEW IF EXISTS public.dash_kpi_mttr CASCADE;
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

-- -------------------------------------------------------------
-- 4. KPI: Weaponized Risks with target support
-- -------------------------------------------------------------
DROP VIEW IF EXISTS public.dash_kpi_weaponized CASCADE;
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

-- -------------------------------------------------------------
-- 5. KPI: SLA Compliance with target support
-- -------------------------------------------------------------
DROP VIEW IF EXISTS public.dash_kpi_compliance CASCADE;
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

-- -------------------------------------------------------------
-- 6. View: Remediation Compliance (Open) - Corrected Aggregation
-- -------------------------------------------------------------
DROP VIEW IF EXISTS public.remediation_open_filtered CASCADE;
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
findings_stats AS (
  SELECT
    f.target,
    CASE
      WHEN bool_or(UPPER(COALESCE(c.cvss_v3_severity, 'MEDIUM')) = 'CRITICAL') THEN 'Critical'
      WHEN bool_or(UPPER(COALESCE(c.cvss_v3_severity, 'MEDIUM')) = 'HIGH')     THEN 'High'
      WHEN bool_or(UPPER(COALESCE(c.cvss_v3_severity, 'MEDIUM')) = 'MEDIUM')   THEN 'Medium'
      ELSE 'Low'
    END as sev,
    COUNT(DISTINCT f.id) as total_count,
    COUNT(DISTINCT f.id) FILTER (WHERE (now() - f.created_at) <= (
      CASE
        WHEN bool_or(UPPER(COALESCE(c.cvss_v3_severity, 'MEDIUM')) = 'CRITICAL') THEN 7
        WHEN bool_or(UPPER(COALESCE(c.cvss_v3_severity, 'MEDIUM')) = 'HIGH')     THEN 30
        WHEN bool_or(UPPER(COALESCE(c.cvss_v3_severity, 'MEDIUM')) = 'MEDIUM')   THEN 90
        ELSE 180
      END * interval '1 day')) as in_comp_count
  FROM public.scan_findings f
  LEFT JOIN public.finding_cves fc ON fc.finding_id = f.id
  LEFT JOIN public.cve_catalog c ON c.cve_id = fc.cve_id
  WHERE f.status = 'open'
  GROUP BY f.id, f.target
)
SELECT
  md5(COALESCE(t.target, 'all') || sl.rating)::uuid AS id,
  t.target,
  sl.rating,
  sl.color,
  'last_30_days' AS time_frame,
  COALESCE(SUM(total_count), 0)::int as total_count,
  COALESCE(SUM(in_comp_count), 0)::int as in_comp_count,
  sl.sort_order
FROM sev_levels sl
CROSS JOIN targets t
LEFT JOIN findings_stats f ON f.sev = sl.rating AND f.target = t.target
GROUP BY t.target, sl.rating, sl.color, sl.sort_order;

-- -------------------------------------------------------------
-- 7. View: Remediation Compliance (Closed)
-- -------------------------------------------------------------
DROP VIEW IF EXISTS public.remediation_closed CASCADE;
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
findings_stats AS (
  SELECT
    f.target,
    CASE
      WHEN bool_or(UPPER(COALESCE(c.cvss_v3_severity, 'MEDIUM')) = 'CRITICAL') THEN 'Critical'
      WHEN bool_or(UPPER(COALESCE(c.cvss_v3_severity, 'MEDIUM')) = 'HIGH')     THEN 'High'
      WHEN bool_or(UPPER(COALESCE(c.cvss_v3_severity, 'MEDIUM')) = 'MEDIUM')   THEN 'Medium'
      ELSE 'Low'
    END as sev,
    COUNT(DISTINCT f.id) AS total_count,
    COUNT(DISTINCT f.id) FILTER (WHERE (sr.completed_at - f.created_at) <= (
      CASE
        WHEN bool_or(UPPER(COALESCE(c.cvss_v3_severity, 'MEDIUM')) = 'CRITICAL') THEN 7
        WHEN bool_or(UPPER(COALESCE(c.cvss_v3_severity, 'MEDIUM')) = 'HIGH')     THEN 30
        WHEN bool_or(UPPER(COALESCE(c.cvss_v3_severity, 'MEDIUM')) = 'MEDIUM')   THEN 90
        ELSE 180
      END * interval '1 day')) AS in_comp_count
  FROM public.scan_findings f
  LEFT JOIN public.finding_cves fc ON fc.finding_id = f.id
  LEFT JOIN public.cve_catalog c ON c.cve_id = fc.cve_id
  LEFT JOIN public.scan_results sr ON sr.id = f.scan_id
  WHERE f.status IN ('fixed', 'resolved', 'closed')
  GROUP BY f.id, f.target, sr.completed_at
)
SELECT
  md5(COALESCE(t.target, 'all') || sl.rating || 'closed')::uuid AS id,
  t.target,
  sl.rating,
  sl.color,
  'last_30_days' AS time_frame,
  COALESCE(SUM(total_count), 0)::int as total_count,
  COALESCE(SUM(in_comp_count), 0)::int as in_comp_count,
  sl.sort_order
FROM sev_levels sl
CROSS JOIN targets t
LEFT JOIN findings_stats f ON f.sev = sl.rating AND f.target = t.target
GROUP BY t.target, sl.rating, sl.color, sl.sort_order;

-- -------------------------------------------------------------
-- 8. Grants
-- -------------------------------------------------------------
GRANT SELECT ON
  public.vuln_risk_score,
  public.vuln_daily_open,
  public.dash_kpi_mttr,
  public.dash_kpi_weaponized,
  public.dash_kpi_compliance,
  public.remediation_open_filtered,
  public.remediation_closed
TO anon, authenticated;

COMMIT;

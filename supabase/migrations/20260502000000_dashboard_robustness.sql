-- =============================================================
-- Dashboard Final: Comprehensive Filtering and Metric Accuracy
-- =============================================================

BEGIN;

-- -------------------------------------------------------------
-- 1. KPI: MTTR (Mean Time To Remediate) with target support
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
-- 2. KPI: Weaponized Risks with target support
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
-- 3. KPI: SLA Compliance with target support
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
-- 4. View: Remediation Compliance (Open) - Standardized structure
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
    COUNT(f.id) as total_count,
    COUNT(f.id) FILTER (WHERE (now() - f.created_at) <= (
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
-- 5. View: Remediation Compliance (Closed)
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
    COUNT(f.id) AS total_count,
    COUNT(f.id) FILTER (WHERE (sr.completed_at - f.created_at) <= (
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
-- 6. Grants
-- -------------------------------------------------------------
GRANT SELECT ON
  public.dash_kpi_mttr,
  public.dash_kpi_weaponized,
  public.dash_kpi_compliance,
  public.remediation_open_filtered,
  public.remediation_closed
TO anon, authenticated;

COMMIT;

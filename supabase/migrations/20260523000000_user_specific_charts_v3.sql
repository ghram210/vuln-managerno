-- =============================================================
-- Dashboard Chart Views v3 — User-specific & Full Buckets
-- =============================================================
-- This migration updates all chart views to filter by the
-- currently authenticated user (auth.uid()) and ensures
-- all logical segments (buckets) appear even with 0 values.

BEGIN;

-- 1. Update chart_vulns_by_exprt
CREATE OR REPLACE VIEW public.chart_vulns_by_exprt AS
WITH buckets (sev, segment_name, sort_order, color) AS (
  VALUES
    ('CRITICAL', 'Critical', 1, 'hsl(0 85% 58%)'),
    ('HIGH',     'High',     2, 'hsl(20 95% 60%)'),
    ('MEDIUM',   'Medium',   3, 'hsl(45 95% 58%)'),
    ('LOW',      'Low',      4, 'hsl(35 90% 65%)'),
    ('INFO',     'Info',     5, 'hsl(55 80% 65%)')
),
user_matched AS (
  SELECT DISTINCT fc.cve_id, UPPER(COALESCE(c.cvss_v3_severity,'INFO')) AS sev
  FROM public.scan_results sr
  JOIN public.scan_findings f ON f.scan_id = sr.id
  JOIN public.finding_cves fc ON fc.finding_id = f.id
  JOIN public.cve_catalog c ON c.cve_id = fc.cve_id
  WHERE sr.user_id = auth.uid()
)
SELECT
  b.segment_name,
  COUNT(m.sev)::int AS segment_value,
  b.color AS segment_color,
  b.sort_order
FROM buckets b
LEFT JOIN user_matched m ON m.sev = b.sev
GROUP BY b.segment_name, b.sort_order, b.color
ORDER BY b.sort_order;

-- 2. Update chart_findings_by_type
CREATE OR REPLACE VIEW public.chart_findings_by_type AS
WITH buckets (bucket, sort_order, color) AS (
  VALUES
    ('Vuln',    1, 'hsl(0 85% 58%)'),
    ('Misconf', 2, 'hsl(275 75% 65%)'),
    ('Unknown', 3, 'hsl(195 90% 55%)')
),
bucketed AS (
  SELECT
    CASE UPPER(COALESCE(f.tool,'OTHER'))
      WHEN 'NMAP'   THEN 'Vuln'
      WHEN 'SQLMAP' THEN 'Vuln'
      WHEN 'NIKTO'  THEN 'Misconf'
      WHEN 'FFUF'   THEN 'Misconf'
      ELSE 'Unknown'
    END AS bucket
  FROM public.scan_findings f
  JOIN public.scan_results sr ON sr.id = f.scan_id
  WHERE sr.user_id = auth.uid()
)
SELECT
  b.bucket AS segment_name,
  COUNT(bd.bucket)::int AS segment_value,
  b.color AS segment_color,
  b.sort_order
FROM buckets b
LEFT JOIN bucketed bd ON bd.bucket = b.bucket
GROUP BY b.bucket, b.sort_order, b.color
ORDER BY b.sort_order;

-- 3. Update chart_exploitability_risk
-- Refined logic: Uses the exploits table to match verified/public PoCs for user CVEs.
CREATE OR REPLACE VIEW public.chart_exploitability_risk AS
WITH buckets (bucket, sort_order, color) AS (
  VALUES
    ('Weaponized',  1, 'hsl(140 75% 45%)'),
    ('Public PoC',  2, 'hsl(155 70% 50%)'),
    ('Known CVE',   3, 'hsl(120 60% 55%)'),
    ('Theoretical', 4, 'hsl(95 60% 60%)')
),
user_cves AS (
  SELECT DISTINCT fc.cve_id, UPPER(COALESCE(c.cvss_v3_severity,'NONE')) AS sev
  FROM public.scan_results sr
  JOIN public.scan_findings f ON f.scan_id = sr.id
  JOIN public.finding_cves fc ON fc.finding_id = f.id
  JOIN public.cve_catalog c ON c.cve_id = fc.cve_id
  WHERE sr.user_id = auth.uid()
),
per_cve AS (
  SELECT
    uc.cve_id,
    uc.sev,
    COUNT(e.exploit_db_id) FILTER (WHERE e.verified IS TRUE) AS verified_count,
    COUNT(e.exploit_db_id) AS total_exploits
  FROM user_cves uc
  LEFT JOIN public.exploits e ON e.cve_id = uc.cve_id
  GROUP BY uc.cve_id, uc.sev
),
classified AS (
  SELECT
    CASE
      WHEN verified_count > 0 THEN 'Weaponized'
      WHEN total_exploits > 0 THEN 'Public PoC'
      WHEN sev IN ('NONE','')  THEN 'Theoretical'
      ELSE 'Known CVE'
    END AS bucket
  FROM per_cve
)
SELECT
  b.bucket AS segment_name,
  COUNT(c.bucket)::int AS segment_value,
  b.color AS segment_color,
  b.sort_order
FROM buckets b
LEFT JOIN classified c ON c.bucket = b.bucket
GROUP BY b.bucket, b.sort_order, b.color
ORDER BY b.sort_order;

-- 4. Update chart_attack_vector
CREATE OR REPLACE VIEW public.chart_attack_vector AS
WITH buckets (bucket, sort_order, color) AS (
  VALUES
    ('Network',  1, 'hsl(335 85% 60%)'),
    ('Adjacent', 2, 'hsl(350 85% 65%)'),
    ('Local',    3, 'hsl(315 80% 65%)'),
    ('Physical', 4, 'hsl(290 70% 65%)'),
    ('Unknown',  5, 'hsl(300 50% 65%)')
),
user_cves AS (
  SELECT DISTINCT fc.cve_id, c.cvss_v3_vector
  FROM public.scan_results sr
  JOIN public.scan_findings f ON f.scan_id = sr.id
  JOIN public.finding_cves fc ON fc.finding_id = f.id
  JOIN public.cve_catalog c ON c.cve_id = fc.cve_id
  WHERE sr.user_id = auth.uid()
),
parsed AS (
  SELECT
    CASE
      WHEN cvss_v3_vector ~* '/AV:N(/|$)' THEN 'Network'
      WHEN cvss_v3_vector ~* '/AV:A(/|$)' THEN 'Adjacent'
      WHEN cvss_v3_vector ~* '/AV:L(/|$)' THEN 'Local'
      WHEN cvss_v3_vector ~* '/AV:P(/|$)' THEN 'Physical'
      ELSE 'Unknown'
    END AS bucket
  FROM user_cves
)
SELECT
  b.bucket AS segment_name,
  COUNT(p.bucket)::int AS segment_value,
  b.color AS segment_color,
  b.sort_order
FROM buckets b
LEFT JOIN parsed p ON p.bucket = b.bucket
GROUP BY b.bucket, b.sort_order, b.color
ORDER BY b.sort_order;

-- 5. Update chart_exploit_types
CREATE OR REPLACE VIEW public.chart_exploit_types AS
WITH buckets (label, sort_order, color) AS (
  VALUES
    ('Remote',            1, 'hsl(0 85% 58%)'),
    ('Web App',           2, 'hsl(195 90% 55%)'),
    ('Local Privilege',   3, 'hsl(20 95% 60%)'),
    ('Denial of Service', 4, 'hsl(45 95% 58%)'),
    ('Shellcode',         5, 'hsl(275 75% 65%)'),
    ('Hardware',          6, 'hsl(335 85% 60%)'),
    ('Other',             9, 'hsl(160 70% 50%)')
),
user_exploits AS (
  SELECT DISTINCT e.exploit_db_id, e.type
  FROM public.scan_results sr
  JOIN public.scan_findings f ON f.scan_id = sr.id
  JOIN public.finding_cves fc ON fc.finding_id = f.id
  JOIN public.exploits e ON e.cve_id = fc.cve_id
  WHERE sr.user_id = auth.uid()
),
typed AS (
  SELECT LOWER(COALESCE(NULLIF(TRIM(type), ''), 'unknown')) AS t
  FROM user_exploits
),
labelled AS (
  SELECT
    CASE t
      WHEN 'remote'    THEN 'Remote'
      WHEN 'local'     THEN 'Local Privilege'
      WHEN 'webapps'   THEN 'Web App'
      WHEN 'dos'       THEN 'Denial of Service'
      WHEN 'shellcode' THEN 'Shellcode'
      WHEN 'hardware'  THEN 'Hardware'
      ELSE 'Other'
    END AS label
  FROM typed
)
SELECT
  b.label AS segment_name,
  COUNT(l.label)::int AS segment_value,
  b.color AS segment_color,
  b.sort_order
FROM buckets b
LEFT JOIN labelled l ON l.label = b.label
GROUP BY b.label, b.sort_order, b.color
ORDER BY b.sort_order;

-- 6. Update chart_top_vulnerable_products
CREATE OR REPLACE VIEW public.chart_top_vulnerable_products AS
WITH product_cves AS (
  SELECT
    NULLIF(TRIM(CONCAT_WS(
      ' ',
      INITCAP(NULLIF(f.metadata->>'vendor','')),
      INITCAP(NULLIF(f.metadata->>'product',''))
    )), '') AS product_label,
    fc.cve_id
  FROM public.scan_results sr
  JOIN public.scan_findings f ON f.scan_id = sr.id
  JOIN public.finding_cves fc ON fc.finding_id = f.id
  WHERE f.metadata->>'product' IS NOT NULL
    AND sr.user_id = auth.uid()
),
ranked AS (
  SELECT
    product_label,
    COUNT(DISTINCT cve_id)::int AS cve_count,
    ROW_NUMBER() OVER (ORDER BY COUNT(DISTINCT cve_id) DESC, product_label) AS rn
  FROM product_cves
  WHERE product_label IS NOT NULL
  GROUP BY product_label
),
palette(idx, color) AS (
  VALUES
    (1, 'hsl(185 95% 55%)'),
    (2, 'hsl(195 90% 60%)'),
    (3, 'hsl(175 85% 50%)'),
    (4, 'hsl(205 90% 65%)'),
    (5, 'hsl(165 80% 50%)'),
    (6, 'hsl(215 85% 65%)'),
    (7, 'hsl(190 70% 70%)')
)
SELECT
  r.product_label AS segment_name,
  r.cve_count     AS segment_value,
  p.color         AS segment_color,
  r.rn::int       AS sort_order
FROM ranked r
JOIN palette p ON p.idx = LEAST(r.rn, 7)
WHERE r.rn <= 7
ORDER BY r.rn;

-- 7. Update chart_asset_exposure
CREATE OR REPLACE VIEW public.chart_asset_exposure AS
WITH buckets (exposure_type, sort_order, color) AS (
  VALUES
    ('Web Application', 1, 'hsl(315 95% 52%)'),
    ('External Host',   2, 'hsl(335 88% 58%)'),
    ('Internal Host',   3, 'hsl(350 78% 65%)'),
    ('Network Service', 4, 'hsl(300 70% 60%)'),
    ('Other',           5, 'hsl(320 35% 72%)')
),
classified AS (
  SELECT DISTINCT ON (target)
    target,
    CASE
      -- Full URL targets (http / https scheme)
      WHEN target ~* '^https?://'
        THEN 'Web Application'
      -- Domain-style targets that contain at least one letter before a TLD
      WHEN target ~* '^[a-zA-Z].*\.[a-zA-Z]{2,}'
        AND target !~ '^\d{1,3}\.'
        THEN 'Web Application'
      -- Internal / private IP ranges
      WHEN target ~ '^10\.'
        OR target ~ '^192\.168\.'
        OR target ~ '^172\.(1[6-9]|2[0-9]|3[01])\.'
        OR target ~ '^127\.'
        THEN 'Internal Host'
      -- Public IPv4
      WHEN target ~ '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        THEN 'External Host'
      ELSE
        'Network Service'
    END AS exposure_type
  FROM public.scan_results
  WHERE user_id = auth.uid()
  ORDER BY target, created_at DESC
)
SELECT
  b.exposure_type AS segment_name,
  COUNT(c.exposure_type)::int AS segment_value,
  b.color AS segment_color,
  b.sort_order
FROM buckets b
LEFT JOIN classified c ON c.exposure_type = b.exposure_type
GROUP BY b.exposure_type, b.sort_order, b.color
ORDER BY b.sort_order;

-- Re-grant permissions
GRANT SELECT ON
  public.chart_vulns_by_exprt,
  public.chart_findings_by_type,
  public.chart_exploitability_risk,
  public.chart_attack_vector,
  public.chart_exploit_types,
  public.chart_top_vulnerable_products,
  public.chart_asset_exposure
TO anon, authenticated;

COMMIT;

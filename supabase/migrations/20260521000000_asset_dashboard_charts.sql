-- =============================================================
-- Asset Dashboard Chart Views
-- 6 donut charts — data filtered to auth.uid() only
-- Shows only THIS user's scan results
-- =============================================================

BEGIN;

DROP VIEW IF EXISTS public.asset_chart_severity      CASCADE;
DROP VIEW IF EXISTS public.asset_chart_by_tool       CASCADE;
DROP VIEW IF EXISTS public.asset_chart_exposure      CASCADE;
DROP VIEW IF EXISTS public.asset_chart_exploitability CASCADE;
DROP VIEW IF EXISTS public.asset_chart_attack_vector CASCADE;
DROP VIEW IF EXISTS public.asset_chart_status        CASCADE;

-- -------------------------------------------------------------
-- 1. Finding Severity
--    Source: scan_findings.severity filtered to current user's scans
-- -------------------------------------------------------------
CREATE OR REPLACE VIEW public.asset_chart_severity AS
SELECT
  CASE UPPER(COALESCE(f.severity, 'info'))
    WHEN 'CRITICAL' THEN 'Critical'
    WHEN 'HIGH'     THEN 'High'
    WHEN 'MEDIUM'   THEN 'Medium'
    WHEN 'LOW'      THEN 'Low'
    ELSE                 'Info'
  END AS segment_name,
  COUNT(*)::int AS segment_value
FROM public.scan_findings f
JOIN public.scan_results sr ON sr.id = f.scan_id
WHERE sr.user_id = auth.uid()
GROUP BY 1;

-- -------------------------------------------------------------
-- 2. Findings by Scan Tool
--    Source: scan_findings.tool filtered to current user's scans
-- -------------------------------------------------------------
CREATE OR REPLACE VIEW public.asset_chart_by_tool AS
SELECT
  CASE UPPER(COALESCE(f.tool, 'other'))
    WHEN 'NMAP'   THEN 'Nmap'
    WHEN 'NIKTO'  THEN 'Nikto'
    WHEN 'SQLMAP' THEN 'SQLMap'
    WHEN 'FFUF'   THEN 'FFUF'
    ELSE               'Other'
  END AS segment_name,
  COUNT(*)::int AS segment_value
FROM public.scan_findings f
JOIN public.scan_results sr ON sr.id = f.scan_id
WHERE sr.user_id = auth.uid()
GROUP BY 1;

-- -------------------------------------------------------------
-- 3. Asset Exposure
--    Source: scan_results.target classified by type (current user only)
-- -------------------------------------------------------------
CREATE OR REPLACE VIEW public.asset_chart_exposure AS
WITH classified AS (
  SELECT DISTINCT ON (target)
    target,
    CASE
      WHEN target ~* '^https?://'                               THEN 'Web Application'
      WHEN target ~* '^[a-zA-Z].*\.[a-zA-Z]{2,}'
        AND target !~ '^\d{1,3}\.'                             THEN 'Web Application'
      WHEN target ~ '^10\.'
        OR  target ~ '^192\.168\.'
        OR  target ~ '^172\.(1[6-9]|2[0-9]|3[01])\.'
        OR  target ~ '^127\.'                                  THEN 'Internal Host'
      WHEN target ~ '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'    THEN 'External Host'
      ELSE                                                           'Network Service'
    END AS exposure_type
  FROM public.scan_results
  WHERE user_id = auth.uid()
  ORDER BY target, created_at DESC
)
SELECT
  exposure_type  AS segment_name,
  COUNT(*)::int  AS segment_value
FROM classified
GROUP BY exposure_type;

-- -------------------------------------------------------------
-- 4. Exploitability Risk
--    Source: user's findings → finding_cves → cve_catalog/exploits
-- -------------------------------------------------------------
CREATE OR REPLACE VIEW public.asset_chart_exploitability AS
WITH user_findings AS (
  SELECT f.id
  FROM   public.scan_findings f
  JOIN   public.scan_results sr ON sr.id = f.scan_id
  WHERE  sr.user_id = auth.uid()
),
matched AS (
  SELECT DISTINCT
    fc.cve_id,
    UPPER(COALESCE(c.cvss_v3_severity, 'NONE')) AS sev
  FROM   public.finding_cves fc
  JOIN   user_findings uf   ON uf.id      = fc.finding_id
  JOIN   public.cve_catalog c ON c.cve_id = fc.cve_id
),
with_exploits AS (
  SELECT
    m.cve_id,
    m.sev,
    COUNT(e.id) FILTER (WHERE e.verified IS TRUE)  AS verified_count,
    COUNT(e.id)                                    AS total_exploits
  FROM   matched m
  LEFT JOIN public.exploits e ON e.cve_id = m.cve_id
  GROUP BY m.cve_id, m.sev
)
SELECT
  CASE
    WHEN verified_count > 0                              THEN 'Weaponized'
    WHEN total_exploits > 0                              THEN 'Public PoC'
    WHEN sev IN ('CRITICAL','HIGH','MEDIUM')             THEN 'Known CVE'
    ELSE                                                      'Theoretical'
  END AS segment_name,
  COUNT(*)::int AS segment_value
FROM with_exploits
GROUP BY 1;

-- -------------------------------------------------------------
-- 5. Attack Vector
--    Source: user's findings → finding_cves → cve_catalog vector
-- -------------------------------------------------------------
CREATE OR REPLACE VIEW public.asset_chart_attack_vector AS
WITH user_findings AS (
  SELECT f.id
  FROM   public.scan_findings f
  JOIN   public.scan_results sr ON sr.id = f.scan_id
  WHERE  sr.user_id = auth.uid()
)
SELECT
  CASE
    WHEN c.cvss_v3_vector ~* 'AV:N' THEN 'Network'
    WHEN c.cvss_v3_vector ~* 'AV:A' THEN 'Adjacent'
    WHEN c.cvss_v3_vector ~* 'AV:L' THEN 'Local'
    WHEN c.cvss_v3_vector ~* 'AV:P' THEN 'Physical'
    ELSE                                  'Unknown'
  END AS segment_name,
  COUNT(*)::int AS segment_value
FROM   public.finding_cves fc
JOIN   user_findings uf     ON uf.id      = fc.finding_id
JOIN   public.cve_catalog c ON c.cve_id   = fc.cve_id
GROUP BY 1;

-- -------------------------------------------------------------
-- 6. Finding Status
--    Source: scan_findings.status filtered to current user's scans
-- -------------------------------------------------------------
CREATE OR REPLACE VIEW public.asset_chart_status AS
SELECT
  CASE LOWER(COALESCE(f.status, 'open'))
    WHEN 'open'           THEN 'Open'
    WHEN 'triaged'        THEN 'Triaged'
    WHEN 'in_progress'    THEN 'Triaged'
    WHEN 'fixed'          THEN 'Fixed'
    WHEN 'resolved'       THEN 'Fixed'
    WHEN 'closed'         THEN 'Fixed'
    WHEN 'false_positive' THEN 'False Positive'
    ELSE                       'Open'
  END AS segment_name,
  COUNT(*)::int AS segment_value
FROM public.scan_findings f
JOIN public.scan_results sr ON sr.id = f.scan_id
WHERE sr.user_id = auth.uid()
GROUP BY 1;

-- -------------------------------------------------------------
-- Grants (authenticated users only — anon cannot see user data)
-- -------------------------------------------------------------
GRANT SELECT ON public.asset_chart_severity       TO authenticated;
GRANT SELECT ON public.asset_chart_by_tool        TO authenticated;
GRANT SELECT ON public.asset_chart_exposure       TO authenticated;
GRANT SELECT ON public.asset_chart_exploitability TO authenticated;
GRANT SELECT ON public.asset_chart_attack_vector  TO authenticated;
GRANT SELECT ON public.asset_chart_status         TO authenticated;

COMMIT;

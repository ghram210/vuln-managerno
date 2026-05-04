-- =============================================================
-- Target Specific Report View (v5 - Technical Deep Dive)
-- =============================================================
-- This view consolidates all data needed for a professional,
-- target-specific vulnerability report.
-- v5 Fixes:
-- 1. Adds 'description' and 'platform' to public.exploits.
-- 2. Ensures 'scan_findings' has 'path' for Nikto/FFUF.
-- 3. Aggregates full technical metadata for the report.
-- =============================================================

BEGIN;

-- 1. Infrastructure Upgrades
ALTER TABLE public.scan_findings ADD COLUMN IF NOT EXISTS title    TEXT;
ALTER TABLE public.scan_findings ADD COLUMN IF NOT EXISTS path     TEXT;
ALTER TABLE public.scan_findings ADD COLUMN IF NOT EXISTS severity TEXT DEFAULT 'info';
ALTER TABLE public.scan_findings ADD COLUMN IF NOT EXISTS status   TEXT DEFAULT 'open';
ALTER TABLE public.scan_findings ADD COLUMN IF NOT EXISTS tool     TEXT;
ALTER TABLE public.scan_findings ADD COLUMN IF NOT EXISTS service  TEXT;
ALTER TABLE public.scan_findings ADD COLUMN IF NOT EXISTS evidence TEXT;

ALTER TABLE public.exploits ADD COLUMN IF NOT EXISTS description TEXT;
ALTER TABLE public.exploits ADD COLUMN IF NOT EXISTS platform    TEXT;
ALTER TABLE public.exploits ADD COLUMN IF NOT EXISTS type        TEXT;

-- 2. The View
DROP VIEW IF EXISTS public.target_report_data CASCADE;

CREATE OR REPLACE VIEW public.target_report_data WITH (security_invoker = true) AS
SELECT
  f.id AS finding_id,
  f.scan_id,
  f.target,
  f.tool,
  COALESCE(f.title, f.service, 'Unknown Finding') AS vulnerability_name,
  f.path AS finding_path,
  f.service AS service_info,
  f.evidence AS finding_evidence,
  f.status AS finding_status,
  f.created_at AS detection_date,
  (
    SELECT json_agg(json_build_object(
      'cve_id', c.cve_id,
      'description', c.description,
      'cvss_v3_score', c.cvss_v3_score,
      'cvss_v3_severity', c.cvss_v3_severity,
      'cvss_v3_vector', c.cvss_v3_vector,
      'references_urls', c.references_urls,
      'exploits', (
        SELECT json_agg(json_build_object(
          'title', e.title,
          'description', e.description,
          'platform', e.platform,
          'type', e.type,
          'url', e.exploit_url,
          'verified', e.verified
        ))
        FROM public.exploits e
        WHERE e.cve_id = c.cve_id
      )
    ))
    FROM public.finding_cves fc
    JOIN public.cve_catalog c ON c.cve_id = fc.cve_id
    WHERE fc.finding_id = f.id
  ) AS cve_details,
  -- Calculate a numeric severity score
  COALESCE(
    (
      SELECT MAX(
        CASE 
          WHEN c2.cvss_v3_severity = 'CRITICAL' THEN 4
          WHEN c2.cvss_v3_severity = 'HIGH' THEN 3
          WHEN c2.cvss_v3_severity = 'MEDIUM' THEN 2
          WHEN c2.cvss_v3_severity = 'LOW' THEN 1
          ELSE 0
        END
      )
      FROM public.finding_cves fc2
      JOIN public.cve_catalog c2 ON c2.cve_id = fc2.cve_id
      WHERE fc2.finding_id = f.id
    ),
    CASE 
      WHEN lower(f.severity) = 'critical' THEN 4
      WHEN lower(f.severity) = 'high' THEN 3
      WHEN lower(f.severity) = 'medium' THEN 2
      WHEN lower(f.severity) = 'low' THEN 1
      ELSE 0
    END
  ) AS severity_score,
  sr.name AS scan_name,
  sr.started_at AS scan_start,
  sr.completed_at AS scan_end,
  sr.user_id
FROM public.scan_findings f
LEFT JOIN public.scan_results sr ON sr.id = f.scan_id;

-- Grant access
ALTER VIEW public.target_report_data OWNER TO postgres;
GRANT SELECT ON public.target_report_data TO authenticated;

COMMIT;

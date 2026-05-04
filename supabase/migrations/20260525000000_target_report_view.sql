-- =============================================================
-- Target Specific Report View
-- =============================================================
-- This view consolidates all data needed for a professional,
-- target-specific vulnerability report.
-- =============================================================

BEGIN;

DROP VIEW IF EXISTS public.target_report_data CASCADE;

CREATE OR REPLACE VIEW public.target_report_data AS
SELECT
  f.id AS finding_id,
  f.target,
  f.tool,
  f.title AS vulnerability_name,
  f.path AS finding_path,
  f.service AS service_info,
  f.evidence AS finding_evidence,
  f.status AS finding_status,
  f.created_at AS detection_date,
  c.cve_id,
  c.description AS cve_description,
  c.cvss_v3_score,
  c.cvss_v3_severity,
  c.cvss_v3_vector,
  c.references_urls,
  (
    SELECT json_agg(json_build_object(
      'title', e.title,
      'url', e.exploit_url,
      'verified', e.verified
    ))
    FROM public.exploits e
    WHERE e.cve_id = c.cve_id
  ) AS exploits,
  sr.name AS scan_name,
  sr.started_at AS scan_start,
  sr.completed_at AS scan_end,
  sr.user_id
FROM public.scan_findings f
JOIN public.scan_results sr ON sr.id = f.scan_id
LEFT JOIN public.finding_cves fc ON fc.finding_id = f.id
LEFT JOIN public.cve_catalog c ON c.cve_id = fc.cve_id;

-- Grant access
ALTER VIEW public.target_report_data OWNER TO postgres;
GRANT SELECT ON public.target_report_data TO authenticated;

-- Enable RLS by using the underlying table's security via user_id
-- Since it's a VIEW, we can't enable RLS directly, but Supabase views
-- inherit the permissions of the owner OR can be filtered in the query.
-- Best practice: Create a security definer function or use RLS on the tables.
-- The underlying scan_results table ALREADY has RLS in strict_rbac.sql.

COMMIT;

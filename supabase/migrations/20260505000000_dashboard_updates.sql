-- =============================================================
-- Dashboard Updates: Enhanced mapping and filtering support
-- =============================================================

BEGIN;

-- 1. Enhanced Status Overview with proper mapping
DROP VIEW IF EXISTS public.vuln_status_overview CASCADE;
CREATE OR REPLACE VIEW public.vuln_status_overview AS
SELECT 
  md5(COALESCE(target, 'all') || mapped_status)::uuid AS id,
  target,
  mapped_status as label,
  COUNT(DISTINCT id)::int AS value
FROM (
  SELECT 
    id, 
    target,
    CASE 
      WHEN status = 'open' THEN 'open'
      WHEN status = 'triaged' THEN 'in_progress'
      WHEN status IN ('fixed', 'resolved', 'closed') THEN 'fixed'
      WHEN status = 'false_positive' THEN 'suppressed'
      ELSE 'open'
    END as mapped_status
  FROM public.scan_findings
) sub
GROUP BY target, mapped_status;

-- 2. Update Top Assets to remove LIMIT 5 from view (handle in frontend)
DROP VIEW IF EXISTS public.vuln_top_assets CASCADE;
CREATE OR REPLACE VIEW public.vuln_top_assets AS
WITH asset_risk AS (
  SELECT 
    f.target,
    COUNT(DISTINCT f.id) as risk_count
  FROM public.scan_findings f
  LEFT JOIN public.finding_cves fc ON fc.finding_id = f.id
  LEFT JOIN public.cve_catalog c ON c.cve_id = fc.cve_id
  WHERE f.status = 'open' 
    AND UPPER(COALESCE(c.cvss_v3_severity, 'MEDIUM')) IN ('CRITICAL', 'HIGH')
  GROUP BY f.target
)
SELECT 
  md5(target)::uuid as id,
  target as label,
  risk_count::int as value,
  'hsl(0 84% 60%)' as color,
  1 as sort_order
FROM asset_risk;

-- 3. Ensure all charts have target for filtering
-- Already present in most, just confirming.

GRANT SELECT ON ALL TABLES IN SCHEMA public TO anon, authenticated;

COMMIT;

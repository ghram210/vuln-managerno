-- Drop and recreate the vulnerabilities view to avoid column name mismatch errors
DROP VIEW IF EXISTS public.vulnerabilities;

CREATE OR REPLACE VIEW public.vulnerabilities WITH (security_invoker = true) AS
WITH cve_findings AS (
    SELECT
        fc.cve_id,
        COUNT(DISTINCT fc.finding_id)::int AS vulnerability_count,
        BOOL_OR(f.status = 'open') AS any_open,
        BOOL_OR(f.status = 'triaged') AS any_triaged,
        BOOL_OR(f.status = 'fixed') AS any_fixed,
        MIN(f.created_at) AS first_seen,
        string_agg(DISTINCT sr.name, ', ') AS scan_names,
        string_agg(DISTINCT f.target, ', ') AS targets,
        string_agg(DISTINCT f.title, ', ') AS vulnerability_name
    FROM public.finding_cves fc
    JOIN public.scan_findings f ON f.id = fc.finding_id
    JOIN public.scan_results sr ON sr.id = f.scan_id
    GROUP BY fc.cve_id
),
cve_exploits AS (
    SELECT
        TRIM(cve_id) as cve_id,
        COUNT(*)::int AS exploit_count,
        BOOL_OR(verified IS TRUE) AS any_verified
    FROM public.exploits
    WHERE cve_id IS NOT NULL
    GROUP BY TRIM(cve_id)
)
SELECT
    md5('vuln|' || c.cve_id)::uuid AS id,
    c.cve_id AS cve_id,
    CASE UPPER(COALESCE(c.cvss_v3_severity, 'NONE')) WHEN 'CRITICAL' THEN 'Critical' WHEN 'HIGH' THEN 'High' WHEN 'MEDIUM' THEN 'Medium' WHEN 'LOW' THEN 'Low' ELSE 'Info' END AS cvss_severity,
    CASE UPPER(COALESCE(c.cvss_v3_severity, 'NONE')) WHEN 'CRITICAL' THEN 'Critical' WHEN 'HIGH' THEN 'High' WHEN 'MEDIUM' THEN 'Medium' WHEN 'LOW' THEN 'Low' ELSE 'Info' END AS exprt_rating,
    c.description AS description,
    CASE WHEN cf.any_open THEN 'Open' WHEN cf.any_triaged THEN 'In Progress' WHEN cf.any_fixed THEN 'Closed' ELSE 'Open' END AS status,
    CASE
      WHEN ce.any_verified THEN 'Actively Used'
      WHEN ce.exploit_count > 0 THEN 'Available'
      WHEN cf.cve_id IS NOT NULL THEN 'Unproven'
      ELSE 'None'
    END AS exploit_status,
    COALESCE(cf.vulnerability_count, 0) AS vulnerability_count,
    cf.scan_names AS scan_names,
    cf.targets AS targets,
    cf.vulnerability_name AS vulnerability_name,
    CASE WHEN c.references_urls IS NOT NULL AND jsonb_array_length(c.references_urls) > 0 THEN 1 ELSE 0 END AS remediations,
    COALESCE(cf.first_seen, c.published_date, NOW()) AS created_at
FROM public.cve_catalog c
JOIN cve_findings cf ON cf.cve_id = c.cve_id
LEFT JOIN cve_exploits ce ON TRIM(ce.cve_id) = TRIM(c.cve_id);

-- Re-grant access after recreation
GRANT SELECT ON public.vulnerabilities TO authenticated;

-- =============================================================
-- Dashboard User Isolation & Security Hardening (BULLETPROOF VERSION)
-- =============================================================
-- This migration ensures absolute isolation between admin accounts
-- by injecting auth.uid() filters directly into the views.
-- =============================================================

BEGIN;

-- 1. Tables: Forced Isolation & Policy Cleanup
ALTER TABLE public.scan_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scan_results FORCE ROW LEVEL SECURITY;
ALTER TABLE public.scan_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scan_findings FORCE ROW LEVEL SECURITY;
ALTER TABLE public.finding_cves ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.finding_cves FORCE ROW LEVEL SECURITY;

DO $$
DECLARE
    t text;
    pol record;
BEGIN
    FOR t IN SELECT unnest(ARRAY['scan_results', 'scan_findings', 'finding_cves']) LOOP
        FOR pol IN SELECT policyname FROM pg_policies WHERE tablename = t AND schemaname = 'public' LOOP
            EXECUTE format('DROP POLICY IF EXISTS %I ON public.%I', pol.policyname, t);
        END LOOP;
    END LOOP;
END $$;

CREATE POLICY "scan_results_isolation" ON public.scan_results FOR ALL TO authenticated USING (user_id = auth.uid());
CREATE POLICY "scan_findings_isolation" ON public.scan_findings FOR ALL TO authenticated USING (EXISTS (SELECT 1 FROM public.scan_results sr WHERE sr.id = scan_id AND sr.user_id = auth.uid()));
CREATE POLICY "finding_cves_isolation" ON public.finding_cves FOR ALL TO authenticated USING (EXISTS (SELECT 1 FROM public.scan_findings f JOIN public.scan_results sr ON sr.id = f.scan_id WHERE f.id = finding_id AND sr.user_id = auth.uid()));

-- 2. Redefine Views with EXPLICIT User Filtering
-- =============================================================

CREATE OR REPLACE VIEW public.vuln_rating_overview_filtered WITH (security_invoker = true) AS
WITH deduped_findings AS (
  SELECT f.id, f.target,
    CASE
      WHEN bool_or(UPPER(COALESCE(c.cvss_v3_severity, 'MEDIUM')) = 'CRITICAL') THEN 'Critical'
      WHEN bool_or(UPPER(COALESCE(c.cvss_v3_severity, 'MEDIUM')) = 'HIGH')     THEN 'High'
      WHEN bool_or(UPPER(COALESCE(c.cvss_v3_severity, 'MEDIUM')) = 'MEDIUM')   THEN 'Medium'
      ELSE 'Low'
    END as rating
  FROM public.scan_findings f
  JOIN public.scan_results sr ON sr.id = f.scan_id
  LEFT JOIN public.finding_cves fc ON fc.finding_id = f.id
  LEFT JOIN public.cve_catalog c ON c.cve_id = fc.cve_id
  WHERE f.status = 'open' AND sr.user_id = auth.uid()
  GROUP BY f.id, f.target
)
SELECT md5(COALESCE(target, 'all') || rating)::uuid as id, target, rating as label, COUNT(*)::int as value,
  CASE WHEN rating = 'Critical' THEN 'hsl(0 84% 60%)' WHEN rating = 'High' THEN 'hsl(24 95% 53%)' WHEN rating = 'Medium' THEN 'hsl(45 93% 47%)' ELSE 'hsl(142 71% 45%)' END as color,
  CASE WHEN rating = 'Critical' THEN 1 WHEN rating = 'High' THEN 2 WHEN rating = 'Medium' THEN 3 ELSE 4 END as sort_order
FROM deduped_findings GROUP BY target, rating;

CREATE OR REPLACE VIEW public.vuln_top_assets WITH (security_invoker = true) AS
WITH asset_risk AS (
  SELECT f.target, COUNT(DISTINCT f.id) as risk_count
  FROM public.scan_findings f
  JOIN public.scan_results sr ON sr.id = f.scan_id
  LEFT JOIN public.finding_cves fc ON fc.finding_id = f.id
  LEFT JOIN public.cve_catalog c ON c.cve_id = fc.cve_id
  WHERE f.status = 'open' AND sr.user_id = auth.uid() AND UPPER(COALESCE(c.cvss_v3_severity, 'MEDIUM')) IN ('CRITICAL', 'HIGH')
  GROUP BY f.target
)
SELECT md5(target)::uuid as id, target as label, risk_count::int as value, 'hsl(0 84% 60%)' as color, 1 as sort_order
FROM asset_risk ORDER BY risk_count DESC LIMIT 5;

CREATE OR REPLACE VIEW public.vuln_by_tool WITH (security_invoker = true) AS
SELECT md5(COALESCE(f.target, 'all') || f.tool)::uuid as id, f.target, f.tool as label, COUNT(DISTINCT f.id)::int as value,
  CASE WHEN f.tool = 'NMAP' THEN 'hsl(210 70% 55%)' WHEN f.tool = 'NIKTO' THEN 'hsl(280 65% 60%)' WHEN f.tool = 'SQLMAP' THEN 'hsl(340 75% 55%)' WHEN f.tool = 'FFUF' THEN 'hsl(160 60% 45%)' ELSE 'hsl(210 15% 55%)' END as color, 1 as sort_order
FROM public.scan_findings f JOIN public.scan_results sr ON sr.id = f.scan_id
WHERE f.status = 'open' AND sr.user_id = auth.uid() GROUP BY f.target, f.tool;

CREATE OR REPLACE VIEW public.vuln_risk_score WITH (security_invoker = true) AS
WITH finding_factors AS (
  SELECT f.id, f.target, COALESCE((SELECT MAX(c.cvss_v3_score) FROM public.finding_cves fc JOIN public.cve_catalog c ON c.cve_id = fc.cve_id WHERE fc.finding_id = f.id), 5.0) as base_score,
    CASE WHEN EXISTS (SELECT 1 FROM public.finding_cves fc JOIN public.exploits e ON e.cve_id = fc.cve_id WHERE fc.finding_id = f.id AND e.verified IS TRUE) THEN 1.8 WHEN EXISTS (SELECT 1 FROM public.finding_cves fc JOIN public.exploits e ON e.cve_id = fc.cve_id WHERE fc.finding_id = f.id) THEN 1.4 ELSE 1.0 END AS exploit_factor,
    CASE WHEN f.service ~* '(postgres|mysql|sql|oracle|db|mongodb|redis|auth|ldap|ad|kerberos|pax)' THEN 1.5 ELSE 1.0 END AS criticality_factor,
    CASE WHEN f.service ~* '(http|https|ssh|rdp|vnc|ftp|smtp)' THEN 1.2 ELSE 1.0 END AS exposure_factor
  FROM public.scan_findings f JOIN public.scan_results sr ON sr.id = f.scan_id WHERE f.status = 'open' AND sr.user_id = auth.uid()
),
scored_findings AS (
  SELECT target, base_score, (base_score * exploit_factor) - base_score AS exploit_impact, (base_score * exploit_factor * criticality_factor) - (base_score * exploit_factor) AS asset_impact, (base_score * exploit_factor * criticality_factor * exposure_factor) - (base_score * exploit_factor * criticality_factor) AS exposure_impact FROM finding_factors
)
SELECT md5(COALESCE(target, 'all') || label)::uuid AS id, target, label, ROUND(AVG(val), 1) AS value, color, sort_order FROM (
  SELECT target, 'Base CVSS' AS label, base_score AS val, 'hsl(210 70% 55%)' AS color, 1 AS sort_order FROM scored_findings UNION ALL
  SELECT target, 'Exploitability' AS label, exploit_impact AS val, 'hsl(0 72% 55%)' AS color, 2 AS sort_order FROM scored_findings UNION ALL
  SELECT target, 'Asset Criticality' AS label, asset_impact AS val, 'hsl(270 60% 55%)' AS color, 3 AS sort_order FROM scored_findings UNION ALL
  SELECT target, 'Exposure' AS label, exposure_impact AS val, 'hsl(30 90% 55%)' AS color, 4 AS sort_order FROM scored_findings
) sub GROUP BY target, label, color, sort_order;

CREATE OR REPLACE VIEW public.vuln_daily_open WITH (security_invoker = true) AS
WITH RECURSIVE days AS ( SELECT (CURRENT_DATE - INTERVAL '44 days')::DATE AS day_date, 1 AS day_num UNION ALL SELECT (day_date + INTERVAL '1 day')::DATE, day_num + 1 FROM days WHERE day_num < 45 ),
targets AS ( SELECT DISTINCT f.target FROM public.scan_findings f JOIN public.scan_results sr ON sr.id = f.scan_id WHERE sr.user_id = auth.uid() )
SELECT md5(d.day_date::text || COALESCE(t.target, 'all'))::uuid AS id, t.target, d.day_num AS day, COUNT(DISTINCT f.id)::int AS count
FROM days d CROSS JOIN targets t LEFT JOIN public.scan_findings f ON f.created_at::date <= d.day_date AND f.target = t.target AND (f.status = 'open' OR (f.status IN ('fixed', 'resolved', 'closed', 'false_positive') AND EXISTS (SELECT 1 FROM public.scan_results sr WHERE sr.id = f.scan_id AND sr.user_id = auth.uid() AND (sr.completed_at::date > d.day_date OR sr.completed_at IS NULL))))
GROUP BY d.day_date, d.day_num, t.target;

CREATE OR REPLACE VIEW public.dash_kpi_mttr WITH (security_invoker = true) AS
SELECT md5(COALESCE(f.target, 'all'))::uuid as id, f.target, 'MTTR' AS label, COALESCE(ROUND(AVG(EXTRACT(EPOCH FROM (sr.completed_at - f.created_at)) / 86400)), 0)::int AS value, 'Days' AS unit, 'hsl(190 65% 58%)' AS color
FROM public.scan_findings f JOIN public.scan_results sr ON sr.id = f.scan_id WHERE f.status IN ('fixed', 'resolved', 'closed') AND sr.completed_at IS NOT NULL AND sr.user_id = auth.uid() GROUP BY f.target;

CREATE OR REPLACE VIEW public.dash_kpi_weaponized WITH (security_invoker = true) AS
SELECT md5(COALESCE(f.target, 'all'))::uuid as id, f.target, 'Weaponized' AS label, COUNT(DISTINCT f.id)::int AS value, 'Risks' AS unit, 'hsl(355 70% 62%)' AS color
FROM public.scan_findings f JOIN public.scan_results sr ON sr.id = f.scan_id WHERE f.status = 'open' AND sr.user_id = auth.uid() AND EXISTS ( SELECT 1 FROM public.finding_cves fc JOIN public.exploits e ON e.cve_id = fc.cve_id WHERE fc.finding_id = f.id AND e.verified IS TRUE ) GROUP BY f.target;

CREATE OR REPLACE VIEW public.dash_kpi_compliance WITH (security_invoker = true) AS
WITH finding_sla AS ( SELECT f.id, f.target, f.created_at, CASE WHEN bool_or(UPPER(COALESCE(c.cvss_v3_severity, 'MEDIUM')) = 'CRITICAL') THEN 7 WHEN bool_or(UPPER(COALESCE(c.cvss_v3_severity, 'MEDIUM')) = 'HIGH') THEN 30 WHEN bool_or(UPPER(COALESCE(c.cvss_v3_severity, 'MEDIUM')) = 'MEDIUM') THEN 90 ELSE 180 END as allowed_days FROM public.scan_findings f JOIN public.scan_results sr ON sr.id = f.scan_id LEFT JOIN public.finding_cves fc ON fc.finding_id = f.id LEFT JOIN public.cve_catalog c ON c.cve_id = fc.cve_id WHERE f.status = 'open' AND sr.user_id = auth.uid() GROUP BY f.id, f.target, f.created_at )
SELECT md5(COALESCE(target, 'all'))::uuid as id, target, 'Compliance' as label, CASE WHEN COUNT(*) = 0 THEN 100 ELSE ROUND((COUNT(*) FILTER (WHERE (now() - created_at) <= (allowed_days * interval '1 day'))::float / COUNT(*)::float) * 100)::int END as value, '%' as unit, 'hsl(155 50% 55%)' as color FROM finding_sla GROUP BY target;

CREATE OR REPLACE VIEW public.remediation_open_filtered WITH (security_invoker = true) AS
WITH sev_levels(rating, color, sort_order, allowed_days) AS ( VALUES ('Critical', 'hsl(0 84% 60%)', 1, 7), ('High', 'hsl(24 95% 53%)', 2, 30), ('Medium', 'hsl(45 93% 47%)', 3, 90), ('Low', 'hsl(142 71% 45%)', 4, 180) ),
targets AS ( SELECT DISTINCT f.target FROM public.scan_findings f JOIN public.scan_results sr ON sr.id = f.scan_id WHERE sr.user_id = auth.uid() ),
finding_info AS ( SELECT f.id, f.target, f.created_at, CASE WHEN bool_or(UPPER(COALESCE(c.cvss_v3_severity, 'MEDIUM')) = 'CRITICAL') THEN 'Critical' WHEN bool_or(UPPER(COALESCE(c.cvss_v3_severity, 'MEDIUM')) = 'HIGH') THEN 'High' WHEN bool_or(UPPER(COALESCE(c.cvss_v3_severity, 'MEDIUM')) = 'MEDIUM') THEN 'Medium' ELSE 'Low' END as sev FROM public.scan_findings f JOIN public.scan_results sr ON sr.id = f.scan_id LEFT JOIN public.finding_cves fc ON fc.finding_id = f.id LEFT JOIN public.cve_catalog c ON c.cve_id = fc.cve_id WHERE f.status = 'open' AND sr.user_id = auth.uid() GROUP BY f.id, f.target, f.created_at )
SELECT md5(COALESCE(t.target, 'all') || sl.rating)::uuid AS id, t.target, sl.rating, sl.color, 'last_30_days' AS time_frame, COUNT(f.id)::int as total_count, COUNT(f.id) FILTER (WHERE (now() - f.created_at) <= (sl.allowed_days * interval '1 day'))::int as in_comp_count, sl.sort_order
FROM sev_levels sl CROSS JOIN targets t LEFT JOIN finding_info f ON f.sev = sl.rating AND f.target = t.target GROUP BY t.target, sl.rating, sl.color, sl.sort_order, sl.allowed_days;

CREATE OR REPLACE VIEW public.remediation_closed WITH (security_invoker = true) AS
WITH sev_levels(rating, color, sort_order, allowed_days) AS ( VALUES ('Critical', 'hsl(142 71% 45%)', 1, 7), ('High', 'hsl(142 71% 45%)', 2, 30), ('Medium', 'hsl(142 71% 45%)', 3, 90), ('Low', 'hsl(142 71% 45%)', 4, 180) ),
targets AS ( SELECT DISTINCT f.target FROM public.scan_findings f JOIN public.scan_results sr ON sr.id = f.scan_id WHERE sr.user_id = auth.uid() ),
finding_info AS ( SELECT f.id, f.target, f.created_at, sr.completed_at, CASE WHEN bool_or(UPPER(COALESCE(c.cvss_v3_severity, 'MEDIUM')) = 'CRITICAL') THEN 'Critical' WHEN bool_or(UPPER(COALESCE(c.cvss_v3_severity, 'MEDIUM')) = 'HIGH') THEN 'High' WHEN bool_or(UPPER(COALESCE(c.cvss_v3_severity, 'MEDIUM')) = 'MEDIUM') THEN 'Medium' ELSE 'Low' END as sev FROM public.scan_findings f JOIN public.scan_results sr ON sr.id = f.scan_id LEFT JOIN public.finding_cves fc ON fc.finding_id = f.id LEFT JOIN public.cve_catalog c ON c.cve_id = fc.cve_id WHERE f.status IN ('fixed', 'resolved', 'closed') AND sr.user_id = auth.uid() GROUP BY f.id, f.target, f.created_at, sr.completed_at )
SELECT md5(COALESCE(t.target, 'all') || sl.rating || 'closed')::uuid AS id, t.target, sl.rating, sl.color, 'last_30_days' AS time_frame, COUNT(f.id)::int as total_count, COUNT(f.id) FILTER (WHERE (f.completed_at - f.created_at) <= (sl.allowed_days * interval '1 day'))::int as in_comp_count, sl.sort_order
FROM sev_levels sl CROSS JOIN targets t LEFT JOIN finding_info f ON f.sev = sl.rating AND f.target = t.target GROUP BY t.target, sl.rating, sl.color, sl.sort_order, sl.allowed_days;

CREATE OR REPLACE VIEW public.vuln_status_overview WITH (security_invoker = true) AS
SELECT md5(COALESCE(f.target, 'all') || f.status)::uuid AS id, f.target, f.status as label, COUNT(DISTINCT f.id)::int AS value
FROM public.scan_findings f JOIN public.scan_results sr ON sr.id = f.scan_id WHERE sr.user_id = auth.uid() GROUP BY f.target, f.status;

CREATE OR REPLACE VIEW public.vulnerabilities WITH (security_invoker = true) AS
WITH cve_findings AS ( SELECT fc.cve_id, COUNT(DISTINCT fc.finding_id)::int AS vulnerability_count, BOOL_OR(f.status = 'open') AS any_open, BOOL_OR(f.status = 'triaged') AS any_triaged, BOOL_OR(f.status = 'fixed') AS any_fixed, MIN(f.created_at) AS first_seen FROM public.finding_cves fc JOIN public.scan_findings f ON f.id = fc.finding_id JOIN public.scan_results sr ON sr.id = f.scan_id WHERE sr.user_id = auth.uid() GROUP BY fc.cve_id ),
cve_exploits AS ( SELECT cve_id, COUNT(*)::int AS exploit_count, BOOL_OR(verified IS TRUE) AS any_verified FROM public.exploits WHERE cve_id IS NOT NULL GROUP BY cve_id )
SELECT md5('vuln|' || c.cve_id)::uuid AS id, c.cve_id AS cve_id, CASE UPPER(COALESCE(c.cvss_v3_severity, 'NONE')) WHEN 'CRITICAL' THEN 'Critical' WHEN 'HIGH' THEN 'High' WHEN 'MEDIUM' THEN 'Medium' WHEN 'LOW' THEN 'Low' ELSE 'Info' END AS cvss_severity, CASE UPPER(COALESCE(c.cvss_v3_severity, 'NONE')) WHEN 'CRITICAL' THEN 'Critical' WHEN 'HIGH' THEN 'High' WHEN 'MEDIUM' THEN 'Medium' WHEN 'LOW' THEN 'Low' ELSE 'Info' END AS exprt_rating, c.description AS description, CASE WHEN cf.any_open THEN 'Open' WHEN cf.any_triaged THEN 'In Progress' WHEN cf.any_fixed THEN 'Closed' ELSE 'Open' END AS status, CASE WHEN ce.any_verified THEN 'Actively Used' WHEN ce.exploit_count > 0 THEN 'Available' ELSE 'None' END AS exploit_status, COALESCE(cf.vulnerability_count, 0) AS vulnerability_count, CASE WHEN c.references_urls IS NOT NULL AND jsonb_array_length(c.references_urls) > 0 THEN 1 ELSE 0 END AS remediations, COALESCE(cf.first_seen, c.published_date, NOW()) AS created_at
FROM public.cve_catalog c JOIN cve_findings cf ON cf.cve_id = c.cve_id LEFT JOIN cve_exploits ce ON ce.cve_id = c.cve_id;

CREATE OR REPLACE VIEW public.scanned_assets WITH (security_invoker = true) AS
WITH latest_scans AS ( SELECT DISTINCT ON (target, tool) * FROM public.scan_results WHERE user_id = auth.uid() ORDER BY target, tool, COALESCE(completed_at, started_at, created_at) DESC ),
scan_ports AS ( SELECT f.scan_id, string_agg(DISTINCT substring(f.target from ':(\d+)'), ',') AS port_list FROM public.scan_findings f GROUP BY f.scan_id ),
fallback_ports AS ( SELECT id, substring(target from ':(\d+)') AS port FROM public.scan_results WHERE target ~ ':\d+' )
SELECT md5('asset|' || ls.target || '|' || COALESCE(ls.tool, 'none'))::uuid AS id, COALESCE(NULLIF(regexp_replace(ls.target, '^https?://', ''), ''), ls.target) AS ip_address, COALESCE(NULLIF(split_part(regexp_replace(ls.target, '^https?://', ''), '/', 1), ''), ls.target) AS hostname, 'unknown'::text AS os, UPPER(ls.tool) AS tool, COALESCE(NULLIF(sp.port_list, ''), NULLIF(fp.port, ''), CASE WHEN ls.target ~* '^https' THEN '443' WHEN ls.target ~* '^http' THEN '80' ELSE '' END) AS open_ports, CASE WHEN ls.critical_count > 0 THEN 'Critical' WHEN ls.high_count > 0 THEN 'High' WHEN ls.medium_count > 0 THEN 'Medium' WHEN ls.low_count > 0 THEN 'Low' ELSE 'Info' END AS risk, COALESCE(ls.completed_at, ls.started_at, ls.created_at) AS last_scan, ls.created_at AS created_at
FROM latest_scans ls LEFT JOIN scan_ports sp ON sp.scan_id = ls.id LEFT JOIN fallback_ports fp ON fp.id = ls.id;

GRANT SELECT ON ALL TABLES IN SCHEMA public TO authenticated;

COMMIT;

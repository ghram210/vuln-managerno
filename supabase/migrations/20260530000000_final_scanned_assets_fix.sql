-- =============================================================
-- Final Scanned Assets View: Guaranteed Ports (with Fallback), Tool, and Isolation
-- =============================================================

BEGIN;

DROP VIEW IF EXISTS public.scanned_assets CASCADE;

CREATE VIEW public.scanned_assets AS
WITH latest_scans AS (
  -- Pick the most recent scan per (target, tool) for the current user
  SELECT DISTINCT ON (target, tool)
    *
  FROM public.scan_results
  WHERE user_id = auth.uid()
  ORDER BY target, tool, COALESCE(completed_at, started_at, created_at) DESC
),
scan_ports AS (
  -- Aggregate ports using the specific scan_id
  SELECT
    f.scan_id,
    string_agg(DISTINCT NULLIF(split_part(f.target, ':', 2), ''), ',') AS port_list
  FROM public.scan_findings f
  GROUP BY f.scan_id
),
target_ports_fallback AS (
  -- Fallback: aggregate ports by target string
  SELECT
    f.target,
    string_agg(DISTINCT NULLIF(split_part(f.target, ':', 2), ''), ',') AS port_list
  FROM public.scan_findings f
  GROUP BY f.target
)
SELECT
  md5('asset|' || ls.target || '|' || COALESCE(ls.tool, 'none'))::uuid AS id,
  COALESCE(NULLIF(regexp_replace(ls.target, '^https?://', ''), ''), ls.target) AS ip_address,
  COALESCE(NULLIF(split_part(regexp_replace(ls.target, '^https?://', ''), '/', 1), ''), ls.target) AS hostname,
  'unknown'::text AS os,
  UPPER(ls.tool) AS tool,
  COALESCE(NULLIF(sp.port_list, ''), tp.port_list, '') AS open_ports,
  CASE
    WHEN ls.critical_count > 0 THEN 'Critical'
    WHEN ls.high_count     > 0 THEN 'High'
    WHEN ls.medium_count   > 0 THEN 'Medium'
    WHEN ls.low_count      > 0 THEN 'Low'
    ELSE 'Info'
  END AS risk,
  COALESCE(ls.completed_at, ls.started_at, ls.created_at) AS last_scan,
  ls.created_at AS created_at
FROM latest_scans ls
LEFT JOIN scan_ports sp ON sp.scan_id = ls.id
LEFT JOIN target_ports_fallback tp ON tp.target = ls.target;

GRANT SELECT ON public.scanned_assets TO authenticated;
GRANT SELECT ON public.scanned_assets TO anon;

COMMIT;

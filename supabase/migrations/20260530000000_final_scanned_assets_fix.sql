-- =============================================================
-- Final Scanned Assets View: Fix Tool, Ports, and Schema Conflicts
-- =============================================================

BEGIN;

DROP VIEW IF EXISTS public.scanned_assets CASCADE;

CREATE VIEW public.scanned_assets AS
WITH raw_data AS (
  SELECT
    id,
    user_id,
    tool,
    -- Normalize target for grouping
    regexp_replace(regexp_replace(lower(trim(target)), '^https?://', ''), '/$', '') AS normalized_target,
    completed_at,
    started_at,
    created_at,
    critical_count,
    high_count,
    medium_count,
    low_count
  FROM public.scan_results
  WHERE user_id = auth.uid()
),
latest_scans AS (
  SELECT DISTINCT ON (normalized_target, tool)
    *
  FROM raw_data
  ORDER BY normalized_target, tool, COALESCE(completed_at, started_at, created_at) DESC
),
per_target_ports AS (
  -- Aggregate ports by host (stripped of protocol and port suffix for joining)
  SELECT
    regexp_replace(regexp_replace(regexp_replace(lower(trim(f.target)), ':\d+$', ''), '^https?://', ''), '/$', '') AS join_host,
    string_agg(DISTINCT NULLIF(split_part(trim(f.target), ':', 2), ''), ',') AS port_list
  FROM public.scan_findings f
  JOIN public.scan_results sr ON sr.id = f.scan_id
  WHERE sr.user_id = auth.uid()
  GROUP BY 1
)
SELECT
  md5('asset|' || ls.normalized_target || '|' || COALESCE(ls.tool, 'none'))::uuid AS id,
  ls.normalized_target AS ip_address,
  ls.normalized_target AS hostname,
  'unknown'::text AS os,
  UPPER(ls.tool) AS tool,
  COALESCE(ptp.port_list, '') AS open_ports, -- Fixed: now correctly joins using normalized host
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
LEFT JOIN per_target_ports ptp ON
  regexp_replace(ls.normalized_target, ':\d+$', '') = ptp.join_host;

GRANT SELECT ON public.scanned_assets TO authenticated;
GRANT SELECT ON public.scanned_assets TO anon;

COMMIT;

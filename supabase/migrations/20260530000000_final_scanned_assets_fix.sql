-- =============================================================
-- Final Scanned Assets View: Precise Tool Identification and Deduplication
-- =============================================================

BEGIN;

CREATE OR REPLACE VIEW public.scanned_assets AS
WITH raw_data AS (
  SELECT
    sr.id,
    sr.user_id,
    -- Try to get the tool name: 1. From scan_results.tool, 2. From first associated finding, 3. Default to 'N/A'
    UPPER(TRIM(COALESCE(
      NULLIF(sr.tool, ''),
      (SELECT tool FROM public.scan_findings f WHERE f.scan_id = sr.id LIMIT 1),
      'N/A'
    ))) AS clean_tool,
    -- Normalize target: trim, lowercase, strip protocol, strip trailing slash
    regexp_replace(
      regexp_replace(
        lower(trim(sr.target)),
        '^https?://',
        ''
      ),
      '/$',
      ''
    ) AS normalized_target,
    sr.completed_at,
    sr.started_at,
    sr.created_at,
    sr.critical_count,
    sr.high_count,
    sr.medium_count,
    sr.low_count
  FROM public.scan_results sr
  WHERE sr.user_id = auth.uid()
),
latest_scans AS (
  -- One row per (normalized_target, tool)
  -- If tool is still N/A, we still group by it
  SELECT DISTINCT ON (normalized_target, clean_tool)
    *
  FROM raw_data
  ORDER BY normalized_target, clean_tool, COALESCE(completed_at, started_at, created_at) DESC
),
per_target_ports AS (
  SELECT
    regexp_replace(
      regexp_replace(
        lower(trim(target)),
        '^https?://',
        ''
      ),
      '/$',
      ''
    ) AS normalized_target,
    string_agg(DISTINCT NULLIF(split_part(trim(target), ':', 2), ''), ',') AS port_list
  FROM public.scan_findings f
  JOIN public.scan_results sr ON sr.id = f.scan_id
  WHERE sr.user_id = auth.uid()
  GROUP BY 1
)
SELECT
  md5('asset|' || ls.normalized_target || '|' || ls.clean_tool)::uuid AS id,
  ls.normalized_target AS ip_address,
  ls.normalized_target AS hostname,
  ls.clean_tool AS os, -- Tool name stored in OS column for UI
  COALESCE(ptp.port_list, '') AS open_ports,
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
LEFT JOIN per_target_ports ptp ON ptp.normalized_target = ls.normalized_target;

COMMIT;

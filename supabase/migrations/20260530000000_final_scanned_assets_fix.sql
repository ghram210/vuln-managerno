-- =============================================================
-- Final Scanned Assets View: Guaranteed Tool Name and Deduplication
-- =============================================================

BEGIN;

CREATE OR REPLACE VIEW public.scanned_assets AS
WITH raw_data AS (
  SELECT
    id,
    user_id,
    -- Prioritize tool name from scan_results, fallback to 'SCANNER'
    UPPER(TRIM(COALESCE(NULLIF(tool, ''), 'SCANNER'))) AS tool_name,
    -- Normalize target: trim, lowercase, strip protocol, strip trailing slash
    regexp_replace(
      regexp_replace(
        lower(trim(target)),
        '^https?://',
        ''
      ),
      '/$',
      ''
    ) AS normalized_target,
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
  -- Pick only the most recent scan for each (target, tool)
  SELECT DISTINCT ON (normalized_target, tool_name)
    *
  FROM raw_data
  ORDER BY normalized_target, tool_name, COALESCE(completed_at, started_at, created_at) DESC
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
  md5('asset|' || ls.normalized_target || '|' || ls.tool_name)::uuid AS id,
  ls.normalized_target AS ip_address,
  ls.normalized_target AS hostname,
  ls.tool_name AS os, -- Map tool_name to the 'os' field for the frontend
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

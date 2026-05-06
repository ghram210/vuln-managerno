-- =============================================================
-- Final Scanned Assets View: Strict Deduplication and Per-Tool Grouping
-- =============================================================
-- This migration ensures that:
-- 1. Assets are deduplicated by normalizing the target URL (stripping protocol and trailing slashes).
-- 2. Results are grouped by both the normalized target AND the tool.
-- 3. Only the most recent scan data for each (target, tool) pair is displayed.
-- 4. Data is isolated to the currently authenticated user.
-- =============================================================

BEGIN;

CREATE OR REPLACE VIEW public.scanned_assets AS
WITH normalized_scans AS (
  SELECT
    id,
    user_id,
    tool,
    target,
    -- Normalize target for grouping: lowercase, strip protocol, strip trailing slash
    regexp_replace(
      regexp_replace(
        lower(target),
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
  -- For each (normalized_target, tool) group, pick the most recent scan record
  SELECT DISTINCT ON (normalized_target, tool)
    *
  FROM normalized_scans
  ORDER BY normalized_target, tool, COALESCE(completed_at, started_at, created_at) DESC
),
per_target_ports AS (
  -- Aggregate ports by normalized target
  SELECT
    regexp_replace(
      regexp_replace(
        lower(target),
        '^https?://',
        ''
      ),
      '/$',
      ''
    ) AS normalized_target,
    string_agg(DISTINCT NULLIF(split_part(target, ':', 2), ''), ',') AS port_list
  FROM public.scan_findings f
  JOIN public.scan_results sr ON sr.id = f.scan_id
  WHERE sr.user_id = auth.uid()
  GROUP BY 1
)
SELECT
  md5('asset|' || ls.normalized_target || '|' || COALESCE(ls.tool, 'none'))::uuid AS id,
  ls.normalized_target AS ip_address, -- Normalized target as IP/ID
  ls.normalized_target AS hostname,   -- Normalized target as Hostname
  COALESCE(UPPER(ls.tool), 'OTHER') AS os, -- Map TOOL to OS column for frontend
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

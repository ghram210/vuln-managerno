-- =============================================================
-- Fix Scanned Assets View for Multi-Tenancy and Per-Tool Grouping
-- =============================================================
-- This migration ensures the `scanned_assets` view only displays
-- data belonging to the currently authenticated user and groups
-- results by both target and tool to avoid duplicate rows for the
-- same tool on the same target.
-- =============================================================

BEGIN;

CREATE OR REPLACE VIEW public.scanned_assets AS
WITH per_target_tool AS (
  SELECT
    sr.target,
    sr.tool,
    -- last scan timestamp for this target/tool pair
    MAX(COALESCE(sr.completed_at, sr.started_at, sr.created_at)) AS last_scan,
    MIN(sr.created_at) AS created_at,
    -- Get severity counts from the MOST RECENT completed scan for this target/tool
    -- to avoid summing across history.
    (
      SELECT critical_count
      FROM public.scan_results sr2
      WHERE sr2.target = sr.target AND sr2.tool = sr.tool AND sr2.user_id = auth.uid()
      ORDER BY COALESCE(sr2.completed_at, sr2.started_at, sr2.created_at) DESC
      LIMIT 1
    ) AS critical_count,
    (
      SELECT high_count
      FROM public.scan_results sr2
      WHERE sr2.target = sr.target AND sr2.tool = sr.tool AND sr2.user_id = auth.uid()
      ORDER BY COALESCE(sr2.completed_at, sr2.started_at, sr2.created_at) DESC
      LIMIT 1
    ) AS high_count,
    (
      SELECT medium_count
      FROM public.scan_results sr2
      WHERE sr2.target = sr.target AND sr2.tool = sr.tool AND sr2.user_id = auth.uid()
      ORDER BY COALESCE(sr2.completed_at, sr2.started_at, sr2.created_at) DESC
      LIMIT 1
    ) AS medium_count,
    (
      SELECT low_count
      FROM public.scan_results sr2
      WHERE sr2.target = sr.target AND sr2.tool = sr.tool AND sr2.user_id = auth.uid()
      ORDER BY COALESCE(sr2.completed_at, sr2.started_at, sr2.created_at) DESC
      LIMIT 1
    ) AS low_count
  FROM public.scan_results sr
  WHERE sr.user_id = auth.uid()
  GROUP BY sr.target, sr.tool
),
per_target_ports AS (
  -- comma-separated list of distinct ports we saw findings on for the current user
  SELECT
    f.target,
    string_agg(DISTINCT NULLIF(split_part(f.target, ':', 2), ''), ',')
      AS port_list
  FROM public.scan_findings f
  JOIN public.scan_results sr ON sr.id = f.scan_id
  WHERE sr.user_id = auth.uid()
  GROUP BY f.target
)
SELECT
  md5('asset|' || pt.target || '|' || COALESCE(pt.tool, 'none'))::uuid AS id,
  -- the "target" in scan_results is typically a URL or host:port.
  -- For the UI we strip scheme/port to get a usable IP/hostname.
  COALESCE(
    NULLIF(regexp_replace(pt.target, '^https?://', ''), ''),
    pt.target
  )                                       AS ip_address,
  COALESCE(
    NULLIF(split_part(
      regexp_replace(pt.target, '^https?://', ''),
      '/', 1), ''),
    pt.target
  )                                       AS hostname,
  pt.tool                                 AS os, -- Hijacking OS column for tool name
  COALESCE(ptp.port_list, '')             AS open_ports,
  CASE
    WHEN pt.critical_count > 0 THEN 'Critical'
    WHEN pt.high_count     > 0 THEN 'High'
    WHEN pt.medium_count   > 0 THEN 'Medium'
    WHEN pt.low_count      > 0 THEN 'Low'
    ELSE 'Info'
  END                                     AS risk,
  pt.last_scan                            AS last_scan,
  pt.created_at                           AS created_at
FROM per_target_tool pt
LEFT JOIN per_target_ports ptp ON ptp.target = pt.target;

COMMIT;

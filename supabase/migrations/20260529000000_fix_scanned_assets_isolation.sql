-- =============================================================
-- Fix Scanned Assets View for Multi-Tenancy
-- =============================================================
-- This migration ensures the `scanned_assets` view only displays
-- data belonging to the currently authenticated user by filtering
-- `scan_results` by `auth.uid()`.
-- =============================================================

BEGIN;

CREATE OR REPLACE VIEW public.scanned_assets AS
WITH per_target AS (
  SELECT
    sr.target,
    -- last scan timestamp
    MAX(COALESCE(sr.completed_at, sr.started_at, sr.created_at))
                                       AS last_scan,
    MIN(sr.created_at)                 AS created_at,
    -- aggregate severity across all scans of this target for the current user
    SUM(sr.critical_count)::int        AS sum_critical,
    SUM(sr.high_count)::int            AS sum_high,
    SUM(sr.medium_count)::int          AS sum_medium,
    SUM(sr.low_count)::int             AS sum_low
  FROM public.scan_results sr
  WHERE sr.user_id = auth.uid()
  GROUP BY sr.target
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
  md5('asset|' || pt.target)::uuid       AS id,
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
  'unknown'::text                         AS os,
  COALESCE(ptp.port_list, '')             AS open_ports,
  CASE
    WHEN pt.sum_critical > 0 THEN 'Critical'
    WHEN pt.sum_high     > 0 THEN 'High'
    WHEN pt.sum_medium   > 0 THEN 'Medium'
    WHEN pt.sum_low      > 0 THEN 'Low'
    ELSE 'Info'
  END                                     AS risk,
  pt.last_scan                            AS last_scan,
  pt.created_at                           AS created_at
FROM per_target pt
LEFT JOIN per_target_ports ptp ON ptp.target = pt.target;

COMMIT;

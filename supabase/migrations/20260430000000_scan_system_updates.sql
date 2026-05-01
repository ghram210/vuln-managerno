-- =============================================================
-- Scan System Updates
-- Adds missing columns and views required by the Scan Gateway
-- =============================================================

-- 1. Ensure raw_output exists for storing tool logs
-- 1. Ensure raw_output and severity columns exist
ALTER TABLE public.scan_results
ADD COLUMN IF NOT EXISTS raw_output TEXT,
ADD COLUMN IF NOT EXISTS critical_count INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS high_count INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS medium_count INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS low_count INTEGER DEFAULT 0;

-- 2. Function to fetch full scan details
-- Used by the gateway to provide detailed status updates
CREATE OR REPLACE FUNCTION public.get_scan_status(p_scan_id TEXT)
RETURNS TABLE(
  id             TEXT,
  name           TEXT,
  target         TEXT,
  tool           TEXT,
  status         TEXT,
  raw_output     TEXT,
  started_at     TIMESTAMPTZ,
  completed_at   TIMESTAMPTZ,
  critical_count INTEGER,
  high_count     INTEGER,
  medium_count   INTEGER,
  low_count      INTEGER,
  total_findings INTEGER
)
LANGUAGE sql
STABLE
SECURITY DEFINER
AS $$
  SELECT
    s.id::text,
    s.name,
    s.target,
    s.tool,
    s.status,
    s.raw_output,
    s.started_at,
    s.completed_at,
    s.critical_count,
    s.high_count,
    s.medium_count,
    s.low_count,
    s.total_findings
  FROM public.scan_results s
  WHERE s.id::text = p_scan_id;
$$;

-- 3. View for active scans
-- Used by the dashboard to show real-time activity
CREATE OR REPLACE VIEW public.running_scans AS
SELECT
  id::text    AS id,
  name,
  target,
  tool,
  status,
  started_at,
  user_id::text AS user_id
FROM public.scan_results
WHERE status = 'running'
ORDER BY started_at DESC;

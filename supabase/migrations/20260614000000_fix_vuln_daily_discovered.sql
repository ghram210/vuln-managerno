-- =============================================================
-- Fix Vulnerability Daily Trend (Deduplicated Cumulative Discovery)
-- =============================================================
-- This migration fixes the inflated vulnerability counts in the dashboard
-- trend chart by deduplicating findings across multiple scans and
-- ensuring strict user isolation.
-- =============================================================

BEGIN;

-- 1. Drop existing views to redefine them
DROP VIEW IF EXISTS public.vuln_daily_open CASCADE;
DROP VIEW IF EXISTS public.vuln_daily_discovered CASCADE;

-- 2. Create the fixed Cumulative Discovery View
CREATE OR REPLACE VIEW public.vuln_daily_discovered WITH (security_invoker = true) AS
WITH RECURSIVE
days AS (
    -- Generate the last 45 days
    SELECT (CURRENT_DATE - INTERVAL '44 days')::DATE AS day_date, 1 AS day_num
    UNION ALL
    SELECT (day_date + INTERVAL '1 day')::DATE, day_num + 1
    FROM days WHERE day_num < 45
),
user_scans AS (
    -- Explicitly filter scans for the current user or their inviter (Admin)
    -- This matches the RLS logic in scan_results_select policy.
    SELECT id
    FROM public.scan_results
    WHERE user_id = auth.uid()
       OR user_id = public.get_inviter_id(auth.uid())
),
unique_vulns AS (
    -- Deduplicate findings into "Unique Vulnerabilities"
    -- A vulnerability is considered unique by its target, tool, title, service and path.
    -- We record the EARLIEST date it was discovered.
    SELECT
        f.target,
        f.tool,
        f.title,
        COALESCE(f.service, '') as service,
        COALESCE(f.path, '') as path,
        MIN(f.created_at)::DATE as first_discovered_at
    FROM public.scan_findings f
    JOIN user_scans us ON us.id = f.scan_id
    GROUP BY f.target, f.tool, f.title, f.service, f.path
),
targets AS (
    -- Get all distinct targets relevant to the user
    SELECT DISTINCT target FROM unique_vulns
)
SELECT
    -- Generate a unique UUID for each (day, target) pair
    md5(d.day_date::text || COALESCE(t.target, 'all'))::uuid AS id,
    t.target,
    d.day_num AS day,
    COUNT(uv.target)::int AS count
FROM days d
CROSS JOIN targets t
LEFT JOIN unique_vulns uv
    ON uv.target = t.target
   AND uv.first_discovered_at <= d.day_date
GROUP BY d.day_date, d.day_num, t.target;

-- 3. Restore the alias view for frontend compatibility
CREATE OR REPLACE VIEW public.vuln_daily_open WITH (security_invoker = true) AS
SELECT * FROM public.vuln_daily_discovered;

-- 4. Re-grant permissions
GRANT SELECT ON public.vuln_daily_discovered TO authenticated;
GRANT SELECT ON public.vuln_daily_open TO authenticated;

COMMIT;

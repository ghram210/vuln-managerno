-- Update the daily trend view to track Cumulative Discovery (Total found up to that date)
-- This maintains original user isolation logic as requested.
BEGIN;

DROP VIEW IF EXISTS public.vuln_daily_open CASCADE;
DROP VIEW IF EXISTS public.vuln_daily_discovered CASCADE;

CREATE OR REPLACE VIEW public.vuln_daily_discovered WITH (security_invoker = true) AS
WITH RECURSIVE days AS (
    SELECT (CURRENT_DATE - INTERVAL '44 days')::DATE AS day_date, 1 AS day_num
    UNION ALL
    SELECT (day_date + INTERVAL '1 day')::DATE, day_num + 1
    FROM days WHERE day_num < 45
),
targets AS (
    SELECT DISTINCT f.target
    FROM public.scan_findings f
    JOIN public.scan_results sr ON sr.id = f.scan_id
    WHERE sr.user_id = auth.uid()
)
SELECT
    md5(d.day_date::text || COALESCE(t.target, 'all'))::uuid AS id,
    t.target,
    d.day_num AS day,
    COUNT(DISTINCT f.id)::int AS count
FROM days d
CROSS JOIN targets t
LEFT JOIN public.scan_findings f ON f.created_at::date <= d.day_date AND f.target = t.target
GROUP BY d.day_date, d.day_num, t.target;

CREATE OR REPLACE VIEW public.vuln_daily_open WITH (security_invoker = true) AS
SELECT * FROM public.vuln_daily_discovered;

GRANT SELECT ON public.vuln_daily_discovered TO authenticated;
GRANT SELECT ON public.vuln_daily_open TO authenticated;

COMMIT;

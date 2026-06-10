-- =============================================================
-- Admin Executive Metrics Migration
-- =============================================================

BEGIN;

CREATE OR REPLACE FUNCTION public.get_admin_executive_stats()
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  result jsonb;
  top_critical jsonb;
  trending jsonb;
  top_users jsonb;
  worst_assets jsonb;
  tech_stack jsonb;
  total_scans_30d bigint;
BEGIN
  -- Check admin role
  IF NOT public.has_role(auth.uid(), 'admin') THEN
    RAISE EXCEPTION 'Access denied';
  END IF;

  -- Total scans in the last 30 days for frequency calculation
  SELECT count(*) INTO total_scans_30d
  FROM public.scan_results
  WHERE created_at > now() - interval '30 days';

  -- 1. Top Critical (30 days)
  -- Aggregates the most frequent critical/high findings
  SELECT json_agg(t) INTO top_critical FROM (
    SELECT title, count(*) as count
    FROM public.scan_findings
    WHERE (severity = 'critical' OR severity = 'high')
      AND created_at > now() - interval '30 days'
    GROUP BY title
    ORDER BY count DESC
    LIMIT 5
  ) t;

  -- 2. Trending (Frequency)
  -- Shows the percentage of scans affected by specific vulnerabilities
  SELECT json_agg(t) INTO trending FROM (
    SELECT
      title,
      count(*) as occurrences,
      CASE
        WHEN total_scans_30d > 0 THEN round((count(DISTINCT scan_id)::float / total_scans_30d::float) * 100)
        ELSE 0
      END as frequency_percent
    FROM public.scan_findings
    WHERE created_at > now() - interval '30 days'
    GROUP BY title
    ORDER BY occurrences DESC
    LIMIT 5
  ) t;

  -- 3. Top Users
  -- Identifies users with the most scan activity
  SELECT json_agg(t) INTO top_users FROM (
    SELECT au.name, count(sr.id) as scan_count
    FROM public.scan_results sr
    JOIN public.admin_users au ON sr.user_id = au.id
    GROUP BY au.name
    ORDER BY scan_count DESC
    LIMIT 5
  ) t;

  -- 4. Worst Assets (Health Score)
  -- Ranks targets by their critical finding count
  SELECT json_agg(t) INTO worst_assets FROM (
    SELECT
      target,
      count(*) filter (where severity = 'critical') as critical_count,
      count(*) filter (where severity = 'high') as high_count,
      count(*) as total_findings
    FROM public.scan_findings
    GROUP BY target
    ORDER BY critical_count DESC, high_count DESC, total_findings DESC
    LIMIT 5
  ) t;

  -- 5. Tech Stack (Vulnerabilities by Category)
  -- Maps tools and findings to logical tech categories
  SELECT json_agg(t) INTO tech_stack FROM (
    SELECT
      category,
      count(*) as count
    FROM (
      SELECT
        CASE
          WHEN lower(tool) = 'sqlmap' OR title ilike '%SQL%' THEN 'Database'
          WHEN lower(tool) IN ('nikto', 'ffuf') OR title ilike '%Web%' OR title ilike '%HTTP%' OR title ilike '%XSS%' OR title ilike '%HTML%' THEN 'Web Application'
          WHEN lower(tool) = 'nmap' OR title ilike '%Port%' OR title ilike '%Service%' OR title ilike '%SSL%' OR title ilike '%TLS%' OR title ilike '%SSH%' THEN 'Network'
          ELSE 'Other'
        END as category
      FROM public.scan_findings
    ) sub
    GROUP BY category
    ORDER BY count DESC
  ) t;

  result := jsonb_build_object(
    'top_critical', COALESCE(top_critical, '[]'::jsonb),
    'trending', COALESCE(trending, '[]'::jsonb),
    'top_users', COALESCE(top_users, '[]'::jsonb),
    'worst_assets', COALESCE(worst_assets, '[]'::jsonb),
    'tech_stack', COALESCE(tech_stack, '[]'::jsonb),
    'total_scans_30d', total_scans_30d
  );

  RETURN result;
END;
$$;

GRANT EXECUTE ON FUNCTION public.get_admin_executive_stats() TO authenticated;

COMMIT;

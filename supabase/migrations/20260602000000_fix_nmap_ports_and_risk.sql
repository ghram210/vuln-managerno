-- كود محدث وأكثر دقة لاستخراج المنافذ وإصلاح منطق المخاطر
DROP VIEW IF EXISTS public.scanned_assets CASCADE;

CREATE VIEW public.scanned_assets AS
WITH latest_scans AS (
  -- اختيار أحدث فحص لكل هدف وأداة للمستخدم الحالي
  SELECT DISTINCT ON (target, tool)
    *
  FROM public.scan_results
  WHERE user_id = auth.uid()
  ORDER BY target, tool, COALESCE(completed_at, started_at, created_at) DESC
),
scan_ports AS (
  -- استخراج أرقام المنافذ من النتائج بـ 3 طرق مختلفة لضمان الدقة
  SELECT 
    scan_id,
    string_agg(DISTINCT port, ',') AS port_list
  FROM (
    -- 1. من حقل الهدف (Target) إذا كان يحتوي على :port
    SELECT scan_id, substring(target from ':(\d+)') AS port
    FROM public.scan_findings
    WHERE target ~ ':\d+'
    UNION
    -- 2. من عنوان النتيجة (Title) إذا كان يحتوي على "Port X"
    SELECT scan_id, substring(title from '(?i)Port\s+(\d+)') AS port
    FROM public.scan_findings
    WHERE title ~* 'Port\s+\d+'
    UNION
    -- 3. من حقل الأدلة (Evidence) مثل "80/tcp open"
    SELECT scan_id, substring(evidence from '(\d+)/tcp') AS port
    FROM public.scan_findings
    WHERE evidence ~ '\d+/tcp'
  ) sub
  GROUP BY scan_id
),
fallback_ports AS (
  -- استخراج المنفذ من هدف الفحص الأساسي
  SELECT 
    id,
    substring(target from ':(\d+)') AS port
  FROM public.scan_results
  WHERE target ~ ':\d+'
)
SELECT
  md5('asset|' || ls.target || '|' || COALESCE(ls.tool, 'none'))::uuid AS id,
  COALESCE(NULLIF(regexp_replace(ls.target, '^https?://', ''), ''), ls.target) AS ip_address,
  COALESCE(NULLIF(split_part(regexp_replace(ls.target, '^https?://', ''), '/', 1), ''), ls.target) AS hostname,
  'unknown'::text AS os, 
  UPPER(ls.tool) AS tool,
  COALESCE(
    NULLIF(sp.port_list, ''), 
    NULLIF(fp.port, ''),
    CASE 
      WHEN ls.target ~* '^https' THEN '443' 
      WHEN ls.target ~* '^http' THEN '80' 
      ELSE '' 
    END
  ) AS open_ports,
  CASE
    WHEN ls.critical_count > 0 THEN 'Critical'
    WHEN ls.high_count     > 0 THEN 'High'
    WHEN ls.medium_count   > 0 THEN 'Medium'
    WHEN ls.low_count      > 0 THEN 'Low'
    WHEN ls.total_findings > 0 THEN 'Info'
    ELSE 'None'
  END AS risk,
  COALESCE(ls.completed_at, ls.started_at, ls.created_at) AS last_scan,
  ls.created_at AS created_at
FROM latest_scans ls
LEFT JOIN scan_ports sp ON sp.scan_id = ls.id
LEFT JOIN fallback_ports fp ON fp.id = ls.id;

GRANT SELECT ON public.scanned_assets TO authenticated;
GRANT SELECT ON public.scanned_assets TO anon;
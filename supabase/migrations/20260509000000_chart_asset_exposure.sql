-- chart_asset_exposure
-- Classifies every distinct scanned target by its real-world type and location:
--   Web Application  → domain/URL target or web port (80/443/8080/8443)
--   External Host    → public IP address
--   Internal Host    → RFC-1918 private IP range
--   Network Service  → anything else (custom ports, unknown protocols)
--
-- Uses scan_findings.target, .service, .port — always populated by the scanner.
-- No extra sync script required.

BEGIN;

DROP VIEW IF EXISTS public.chart_assets_by_risk;
DROP VIEW IF EXISTS public.chart_assets_by_type;
DROP VIEW IF EXISTS public.chart_asset_exposure;

CREATE OR REPLACE VIEW public.chart_asset_exposure AS
WITH classified AS (
  SELECT DISTINCT ON (target)
    target,
    CASE
      -- Domain / URL-style targets (contain letters + dots, start with a letter or http)
      WHEN target ~* '^https?://'
        OR target ~* '^[a-z].*\.(com|net|org|io|edu|gov|co|me|app|dev|local|test|fire|php|vuln)[^a-z]?'
        OR service ~* '^https?$'
        OR port IN (80, 443, 8080, 8443, 8000, 3000)
        THEN 'Web Application'

      -- Private / internal IP ranges
      WHEN target ~ '^10\.'
        OR target ~ '^192\.168\.'
        OR target ~ '^172\.(1[6-9]|2[0-9]|3[01])\.'
        OR target ~ '^127\.'
        THEN 'Internal Host'

      -- Public IP addresses (starts with digits)
      WHEN target ~ '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        THEN 'External Host'

      -- Anything else (IPv6, named service endpoints, etc.)
      ELSE 'Network Service'
    END AS exposure_type

  FROM public.scan_findings
  ORDER BY target, created_at DESC
)
SELECT
  exposure_type            AS segment_name,
  COUNT(*)::int            AS segment_value,
  CASE exposure_type
    WHEN 'Web Application' THEN 'hsl(315 95% 52%)'
    WHEN 'External Host'   THEN 'hsl(335 88% 58%)'
    WHEN 'Internal Host'   THEN 'hsl(350 78% 65%)'
    WHEN 'Network Service' THEN 'hsl(300 70% 60%)'
    ELSE                        'hsl(320 35% 72%)'
  END                      AS segment_color,
  CASE exposure_type
    WHEN 'Web Application' THEN 1
    WHEN 'External Host'   THEN 2
    WHEN 'Internal Host'   THEN 3
    WHEN 'Network Service' THEN 4
    ELSE                        5
  END                      AS sort_order
FROM classified
GROUP BY exposure_type
HAVING COUNT(*) > 0;

GRANT SELECT ON public.chart_asset_exposure TO anon, authenticated;

COMMIT;

-- Fix chart_top_vulnerable_products display names
-- The scanner stores CPE-format product names (http_server, node.js, sql_server…)
-- This view maps them to human-readable labels so the chart shows
-- "Apache HTTP Server" instead of "Http_Server", "OpenSSL" instead of "Openssl", etc.

BEGIN;

DROP VIEW IF EXISTS public.chart_top_vulnerable_products;

CREATE OR REPLACE VIEW public.chart_top_vulnerable_products AS
WITH raw_products AS (
  SELECT
    LOWER(TRIM(COALESCE(f.metadata->>'vendor',  ''))) AS v,
    LOWER(TRIM(COALESCE(f.metadata->>'product', ''))) AS p,
    COUNT(*)::int AS finding_count
  FROM public.scan_findings f
  WHERE COALESCE(TRIM(f.metadata->>'product'), '') <> ''
  GROUP BY
    LOWER(TRIM(COALESCE(f.metadata->>'vendor',  ''))),
    LOWER(TRIM(COALESCE(f.metadata->>'product', '')))
),
labelled AS (
  SELECT
    CASE
      -- Web servers
      WHEN v='apache'       AND p='http_server'  THEN 'Apache HTTP Server'
      WHEN v='nginx'        AND p='nginx'         THEN 'Nginx'
      WHEN v='microsoft'    AND p='iis'           THEN 'Microsoft IIS'
      WHEN v='lighttpd'     AND p='lighttpd'      THEN 'Lighttpd'
      WHEN v='apache'       AND p='tomcat'        THEN 'Apache Tomcat'
      -- CMSs
      WHEN v='wordpress'    AND p='wordpress'     THEN 'WordPress'
      WHEN v='drupal'       AND p='drupal'        THEN 'Drupal'
      WHEN v='joomla'       AND p='joomla!'       THEN 'Joomla'
      WHEN v='magento'      AND p='magento'       THEN 'Magento'
      -- Languages / runtimes
      WHEN v='php'          AND p='php'           THEN 'PHP'
      WHEN v='python'       AND p='python'        THEN 'Python'
      WHEN v='nodejs'       AND p='node.js'       THEN 'Node.js'
      -- Crypto
      WHEN v='openssl'      AND p='openssl'       THEN 'OpenSSL'
      -- JS libraries
      WHEN v='jquery'       AND p='jquery'        THEN 'jQuery'
      WHEN v='getbootstrap' AND p='bootstrap'     THEN 'Bootstrap'
      WHEN v='angularjs'    AND p='angular.js'    THEN 'AngularJS'
      -- Databases
      WHEN v='mysql'        AND p='mysql'         THEN 'MySQL'
      WHEN v='mariadb'      AND p='mariadb'       THEN 'MariaDB'
      WHEN v='postgresql'   AND p='postgresql'    THEN 'PostgreSQL'
      WHEN v='microsoft'    AND p='sql_server'    THEN 'MS SQL Server'
      WHEN v='oracle'       AND p='database'      THEN 'Oracle DB'
      -- Fallback: prettify whatever is stored
      ELSE INITCAP(REPLACE(REPLACE(p, '_', ' '), '.', ' '))
    END AS product_label,
    finding_count
  FROM raw_products
),
merged AS (
  SELECT product_label, SUM(finding_count)::int AS total
  FROM labelled
  WHERE NULLIF(TRIM(product_label), '') IS NOT NULL
  GROUP BY product_label
  ORDER BY total DESC
  LIMIT 7
),
ranked AS (
  SELECT
    product_label,
    total,
    ROW_NUMBER() OVER (ORDER BY total DESC) AS rn
  FROM merged
),
palette (idx, color) AS (
  VALUES
    (1, 'hsl(185 95% 55%)'),
    (2, 'hsl(195 90% 60%)'),
    (3, 'hsl(175 85% 50%)'),
    (4, 'hsl(205 90% 65%)'),
    (5, 'hsl(165 80% 50%)'),
    (6, 'hsl(215 85% 65%)'),
    (7, 'hsl(190 70% 70%)')
)
SELECT
  r.product_label  AS segment_name,
  r.total          AS segment_value,
  p.color          AS segment_color,
  r.rn::int        AS sort_order
FROM ranked r
JOIN palette p ON p.idx = LEAST(r.rn, 7)
ORDER BY r.rn;

GRANT SELECT ON public.chart_top_vulnerable_products TO anon, authenticated;

COMMIT;

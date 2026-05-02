-- =============================================================
-- Dashboard Chart Views v2 — safer migration
-- =============================================================
-- Run in: Supabase Dashboard → SQL Editor → New Query
-- This replaces the previous migration (20260501100000).
-- =============================================================

BEGIN;

-- -------------------------------------------------------------
-- 1a. cve_catalog  (published_date column matches sync script)
-- -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.cve_catalog (
  cve_id            TEXT PRIMARY KEY,
  description       TEXT,
  cvss_v3_score     REAL,
  cvss_v3_severity  TEXT,
  cvss_v3_vector    TEXT,
  published_date    DATE
);
-- Add any missing columns to an existing table
ALTER TABLE public.cve_catalog ADD COLUMN IF NOT EXISTS description      TEXT;
ALTER TABLE public.cve_catalog ADD COLUMN IF NOT EXISTS cvss_v3_score    REAL;
ALTER TABLE public.cve_catalog ADD COLUMN IF NOT EXISTS cvss_v3_severity TEXT;
ALTER TABLE public.cve_catalog ADD COLUMN IF NOT EXISTS cvss_v3_vector   TEXT;
ALTER TABLE public.cve_catalog ADD COLUMN IF NOT EXISTS published_date   DATE;

ALTER TABLE public.cve_catalog ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Anyone can read cve_catalog" ON public.cve_catalog;
CREATE POLICY "Anyone can read cve_catalog"
  ON public.cve_catalog FOR SELECT USING (true);
GRANT SELECT ON public.cve_catalog TO anon, authenticated;

-- -------------------------------------------------------------
-- 1b. exploits  (create first so ALTER TABLE never fails)
-- -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.exploits (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  cve_id        TEXT,
  exploit_db_id INTEGER,
  type          TEXT,
  platform      TEXT,
  verified      BOOLEAN DEFAULT FALSE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Add missing columns if the table already existed without them
ALTER TABLE public.exploits ADD COLUMN IF NOT EXISTS type          TEXT;
ALTER TABLE public.exploits ADD COLUMN IF NOT EXISTS platform      TEXT;
ALTER TABLE public.exploits ADD COLUMN IF NOT EXISTS verified      BOOLEAN DEFAULT FALSE;
ALTER TABLE public.exploits ADD COLUMN IF NOT EXISTS exploit_db_id INTEGER;

ALTER TABLE public.exploits ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Anyone can read exploits" ON public.exploits;
CREATE POLICY "Anyone can read exploits"
  ON public.exploits FOR SELECT USING (true);
GRANT SELECT ON public.exploits TO anon, authenticated;

-- Unique constraint for upsert (on_conflict=exploit_db_id,cve_id)
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'public.exploits'::regclass
      AND conname = 'exploits_exploit_db_id_cve_id_key'
  ) THEN
    ALTER TABLE public.exploits
      ADD CONSTRAINT exploits_exploit_db_id_cve_id_key
      UNIQUE (exploit_db_id, cve_id);
  END IF;
EXCEPTION WHEN others THEN NULL;
END$$;

-- -------------------------------------------------------------
-- 1c. finding_cves
-- -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.finding_cves (
  finding_id  UUID NOT NULL,
  cve_id      TEXT NOT NULL,
  PRIMARY KEY (finding_id, cve_id)
);
ALTER TABLE public.finding_cves ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Anyone can read finding_cves" ON public.finding_cves;
CREATE POLICY "Anyone can read finding_cves"
  ON public.finding_cves FOR SELECT USING (true);
GRANT SELECT ON public.finding_cves TO anon, authenticated;

-- -------------------------------------------------------------
-- 1d. scan_findings — add missing columns
-- -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.scan_findings (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id     UUID,
  target      TEXT,
  tool        TEXT,
  service     TEXT,
  port        INTEGER,
  evidence    TEXT,
  severity    TEXT DEFAULT 'info',
  category    TEXT,
  status      TEXT DEFAULT 'open',
  metadata    JSONB DEFAULT '{}'::jsonb,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE public.scan_findings ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}'::jsonb;
ALTER TABLE public.scan_findings ADD COLUMN IF NOT EXISTS status   TEXT DEFAULT 'open';
ALTER TABLE public.scan_findings ADD COLUMN IF NOT EXISTS tool     TEXT;
ALTER TABLE public.scan_findings ADD COLUMN IF NOT EXISTS service  TEXT;
ALTER TABLE public.scan_findings ADD COLUMN IF NOT EXISTS port     INTEGER;
ALTER TABLE public.scan_findings ADD COLUMN IF NOT EXISTS evidence TEXT;

ALTER TABLE public.scan_findings ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Public can read scan_findings" ON public.scan_findings;
CREATE POLICY "Public can read scan_findings"
  ON public.scan_findings FOR SELECT TO anon, authenticated USING (true);
GRANT SELECT ON public.scan_findings TO anon, authenticated;

-- Indexes
CREATE INDEX IF NOT EXISTS idx_finding_cves_cve_id    ON public.finding_cves(cve_id);
CREATE INDEX IF NOT EXISTS idx_cve_catalog_severity   ON public.cve_catalog(cvss_v3_severity);
CREATE INDEX IF NOT EXISTS idx_exploits_type          ON public.exploits(type);
CREATE INDEX IF NOT EXISTS idx_scan_findings_scan_id  ON public.scan_findings(scan_id);

-- -------------------------------------------------------------
-- 2. Drop old views
-- -------------------------------------------------------------
DROP VIEW IF EXISTS public.chart_vulns_by_exprt          CASCADE;
DROP VIEW IF EXISTS public.chart_findings_by_type        CASCADE;
DROP VIEW IF EXISTS public.chart_exploitability_risk     CASCADE;
DROP VIEW IF EXISTS public.chart_attack_vector           CASCADE;
DROP VIEW IF EXISTS public.chart_exploit_types           CASCADE;
DROP VIEW IF EXISTS public.chart_top_vulnerable_products CASCADE;
DROP VIEW IF EXISTS public.scanned_assets                CASCADE;

-- -------------------------------------------------------------
-- 3. chart_vulns_by_exprt
-- -------------------------------------------------------------
CREATE OR REPLACE VIEW public.chart_vulns_by_exprt AS
WITH matched AS (
  SELECT DISTINCT c.cve_id, UPPER(COALESCE(c.cvss_v3_severity,'NONE')) AS sev
  FROM public.cve_catalog c
  JOIN public.finding_cves fc ON fc.cve_id = c.cve_id
)
SELECT
  CASE sev
    WHEN 'CRITICAL' THEN 'Critical'
    WHEN 'HIGH'     THEN 'High'
    WHEN 'MEDIUM'   THEN 'Medium'
    WHEN 'LOW'      THEN 'Low'
    ELSE 'Info'
  END AS segment_name,
  COUNT(*)::int AS segment_value,
  CASE sev
    WHEN 'CRITICAL' THEN 'hsl(0 85% 58%)'
    WHEN 'HIGH'     THEN 'hsl(20 95% 60%)'
    WHEN 'MEDIUM'   THEN 'hsl(45 95% 58%)'
    WHEN 'LOW'      THEN 'hsl(35 90% 65%)'
    ELSE                 'hsl(55 80% 65%)'
  END AS segment_color,
  CASE sev
    WHEN 'CRITICAL' THEN 1
    WHEN 'HIGH'     THEN 2
    WHEN 'MEDIUM'   THEN 3
    WHEN 'LOW'      THEN 4
    ELSE 5
  END AS sort_order
FROM matched
GROUP BY sev
ORDER BY sort_order;

-- -------------------------------------------------------------
-- 4. chart_findings_by_type
-- -------------------------------------------------------------
CREATE OR REPLACE VIEW public.chart_findings_by_type AS
WITH bucketed AS (
  SELECT
    CASE UPPER(COALESCE(f.tool,'OTHER'))
      WHEN 'NMAP'   THEN 'Vuln'
      WHEN 'SQLMAP' THEN 'Vuln'
      WHEN 'NIKTO'  THEN 'Misconf'
      WHEN 'FFUF'   THEN 'Misconf'
      ELSE 'Unknown'
    END AS bucket
  FROM public.scan_findings f
)
SELECT
  bucket AS segment_name,
  COUNT(*)::int AS segment_value,
  CASE bucket
    WHEN 'Vuln'    THEN 'hsl(0 85% 58%)'
    WHEN 'Misconf' THEN 'hsl(275 75% 65%)'
    ELSE                'hsl(195 90% 55%)'
  END AS segment_color,
  CASE bucket
    WHEN 'Vuln'    THEN 1
    WHEN 'Misconf' THEN 2
    ELSE 3
  END AS sort_order
FROM bucketed
GROUP BY bucket
ORDER BY sort_order;

-- -------------------------------------------------------------
-- 5. chart_exploitability_risk
-- -------------------------------------------------------------
CREATE OR REPLACE VIEW public.chart_exploitability_risk AS
WITH per_cve AS (
  SELECT
    c.cve_id,
    UPPER(COALESCE(c.cvss_v3_severity,'NONE')) AS sev,
    COUNT(e.exploit_db_id) FILTER (WHERE e.verified IS TRUE) AS verified_count,
    COUNT(e.exploit_db_id) AS total_exploits
  FROM public.cve_catalog c
  JOIN public.finding_cves fc ON fc.cve_id = c.cve_id
  LEFT JOIN public.exploits e ON e.cve_id = c.cve_id
  GROUP BY c.cve_id, c.cvss_v3_severity
),
classified AS (
  SELECT
    CASE
      WHEN verified_count > 0 THEN 'Weaponized'
      WHEN total_exploits > 0 THEN 'Public PoC'
      WHEN sev IN ('NONE','')  THEN 'Theoretical'
      ELSE 'Known CVE'
    END AS bucket
  FROM per_cve
)
SELECT
  bucket AS segment_name,
  COUNT(*)::int AS segment_value,
  CASE bucket
    WHEN 'Weaponized'  THEN 'hsl(140 75% 45%)'
    WHEN 'Public PoC'  THEN 'hsl(155 70% 50%)'
    WHEN 'Known CVE'   THEN 'hsl(120 60% 55%)'
    ELSE                    'hsl(95 60% 60%)'
  END AS segment_color,
  CASE bucket
    WHEN 'Weaponized'  THEN 1
    WHEN 'Public PoC'  THEN 2
    WHEN 'Known CVE'   THEN 3
    ELSE 4
  END AS sort_order
FROM classified
GROUP BY bucket
ORDER BY sort_order;

-- -------------------------------------------------------------
-- 6. chart_attack_vector
-- -------------------------------------------------------------
CREATE OR REPLACE VIEW public.chart_attack_vector AS
WITH parsed AS (
  SELECT
    CASE
      WHEN c.cvss_v3_vector ~* '/AV:N(/|$)' THEN 'Network'
      WHEN c.cvss_v3_vector ~* '/AV:A(/|$)' THEN 'Adjacent'
      WHEN c.cvss_v3_vector ~* '/AV:L(/|$)' THEN 'Local'
      WHEN c.cvss_v3_vector ~* '/AV:P(/|$)' THEN 'Physical'
      ELSE 'Unknown'
    END AS bucket
  FROM public.cve_catalog c
  JOIN public.finding_cves fc ON fc.cve_id = c.cve_id
)
SELECT
  bucket AS segment_name,
  COUNT(*)::int AS segment_value,
  CASE bucket
    WHEN 'Network'  THEN 'hsl(335 85% 60%)'
    WHEN 'Adjacent' THEN 'hsl(350 85% 65%)'
    WHEN 'Local'    THEN 'hsl(315 80% 65%)'
    WHEN 'Physical' THEN 'hsl(290 70% 65%)'
    ELSE                 'hsl(300 50% 65%)'
  END AS segment_color,
  CASE bucket
    WHEN 'Network'  THEN 1
    WHEN 'Adjacent' THEN 2
    WHEN 'Local'    THEN 3
    WHEN 'Physical' THEN 4
    ELSE 5
  END AS sort_order
FROM parsed
GROUP BY bucket
ORDER BY sort_order;

-- -------------------------------------------------------------
-- 7. chart_exploit_types  (works as soon as exploits has rows)
-- -------------------------------------------------------------
CREATE OR REPLACE VIEW public.chart_exploit_types AS
WITH typed AS (
  SELECT LOWER(COALESCE(NULLIF(TRIM(e.type), ''), 'unknown')) AS t
  FROM public.exploits e
),
labelled AS (
  SELECT
    CASE t
      WHEN 'remote'    THEN 'Remote'
      WHEN 'local'     THEN 'Local Privilege'
      WHEN 'webapps'   THEN 'Web App'
      WHEN 'dos'       THEN 'Denial of Service'
      WHEN 'shellcode' THEN 'Shellcode'
      WHEN 'hardware'  THEN 'Hardware'
      WHEN 'unknown'   THEN 'Other'
      ELSE INITCAP(t)
    END AS label
  FROM typed
)
SELECT
  label AS segment_name,
  COUNT(*)::int AS segment_value,
  CASE label
    WHEN 'Remote'            THEN 'hsl(0 85% 58%)'
    WHEN 'Web App'           THEN 'hsl(195 90% 55%)'
    WHEN 'Local Privilege'   THEN 'hsl(20 95% 60%)'
    WHEN 'Denial of Service' THEN 'hsl(45 95% 58%)'
    WHEN 'Shellcode'         THEN 'hsl(275 75% 65%)'
    WHEN 'Hardware'          THEN 'hsl(335 85% 60%)'
    WHEN 'Other'             THEN 'hsl(160 70% 50%)'
    ELSE                          'hsl(140 75% 50%)'
  END AS segment_color,
  CASE label
    WHEN 'Remote'            THEN 1
    WHEN 'Web App'           THEN 2
    WHEN 'Local Privilege'   THEN 3
    WHEN 'Denial of Service' THEN 4
    WHEN 'Shellcode'         THEN 5
    WHEN 'Hardware'          THEN 6
    WHEN 'Other'             THEN 9
    ELSE 7
  END AS sort_order
FROM labelled
GROUP BY label
ORDER BY sort_order, label;

-- -------------------------------------------------------------
-- 8. chart_top_vulnerable_products
-- -------------------------------------------------------------
CREATE OR REPLACE VIEW public.chart_top_vulnerable_products AS
WITH product_cves AS (
  SELECT
    NULLIF(TRIM(CONCAT_WS(
      ' ',
      INITCAP(NULLIF(f.metadata->>'vendor','')),
      INITCAP(NULLIF(f.metadata->>'product',''))
    )), '') AS product_label,
    fc.cve_id
  FROM public.scan_findings f
  JOIN public.finding_cves fc ON fc.finding_id = f.id
  WHERE f.metadata->>'product' IS NOT NULL
),
ranked AS (
  SELECT
    product_label,
    COUNT(DISTINCT cve_id)::int AS cve_count,
    ROW_NUMBER() OVER (ORDER BY COUNT(DISTINCT cve_id) DESC, product_label) AS rn
  FROM product_cves
  WHERE product_label IS NOT NULL
  GROUP BY product_label
),
palette(idx, color) AS (
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
  r.product_label AS segment_name,
  r.cve_count     AS segment_value,
  p.color         AS segment_color,
  r.rn::int       AS sort_order
FROM ranked r
JOIN palette p ON p.idx = LEAST(r.rn, 7)
WHERE r.rn <= 7
ORDER BY r.rn;

-- -------------------------------------------------------------
-- 9. scanned_assets view
-- -------------------------------------------------------------
CREATE OR REPLACE VIEW public.scanned_assets AS
WITH per_target AS (
  SELECT
    sr.target,
    MAX(COALESCE(sr.completed_at, sr.started_at, sr.created_at)) AS last_scan,
    MIN(sr.created_at) AS created_at,
    COALESCE(SUM(sr.critical_count),0)::int AS sum_critical,
    COALESCE(SUM(sr.high_count),0)::int     AS sum_high,
    COALESCE(SUM(sr.medium_count),0)::int   AS sum_medium,
    COALESCE(SUM(sr.low_count),0)::int      AS sum_low
  FROM public.scan_results sr
  GROUP BY sr.target
),
finding_ports AS (
  SELECT DISTINCT
    sr.target,
    (regexp_matches(f.evidence, '(\d{1,5})\s*/\s*(?:tcp|udp)', 'gi'))[1]::int AS port_num
  FROM public.scan_findings f
  JOIN public.scan_results sr ON sr.id = f.scan_id
  WHERE f.evidence ~* '\d{1,5}\s*/\s*(?:tcp|udp)'
),
url_ports AS (
  SELECT DISTINCT
    sr.target,
    CASE
      WHEN sr.target ~* '^https://' THEN 443
      WHEN sr.target ~* '^http://'  THEN 80
      WHEN sr.target ~* '^ssh://'   THEN 22
      WHEN sr.target ~* '^ftp://'   THEN 21
      ELSE NULL
    END AS port_num
  FROM public.scan_results sr
  WHERE NOT EXISTS (
    SELECT 1 FROM finding_ports fp WHERE fp.target = sr.target
  )
),
all_ports AS (
  SELECT target, port_num FROM finding_ports WHERE port_num IS NOT NULL
  UNION
  SELECT target, port_num FROM url_ports     WHERE port_num IS NOT NULL
),
target_ports AS (
  SELECT
    target,
    string_agg(port_num::text, ', ' ORDER BY port_num) AS port_list
  FROM (SELECT DISTINCT target, port_num FROM all_ports) d
  GROUP BY target
),
target_os AS (
  SELECT
    sr.target,
    CASE
      WHEN BOOL_OR(
        LOWER(f.service) LIKE 'microsoft-%'
        OR LOWER(f.service) LIKE 'ms-%'
        OR LOWER(f.service) IN ('smb','netbios-ssn','netbios-ns','rdp')
      ) THEN 'Windows'
      WHEN BOOL_OR(
        LOWER(f.service) IN ('ssh','telnet','http','https','nginx','apache','vsftpd','postfix')
      ) THEN 'Linux/Unix'
      ELSE NULL
    END AS os
  FROM public.scan_findings f
  JOIN public.scan_results sr ON sr.id = f.scan_id
  WHERE f.service IS NOT NULL
  GROUP BY sr.target
)
SELECT
  md5('asset|' || pt.target)::uuid AS id,
  COALESCE(
    NULLIF(regexp_replace(pt.target, '^https?://', ''), ''),
    pt.target
  ) AS ip_address,
  COALESCE(
    NULLIF(split_part(regexp_replace(pt.target, '^https?://', ''), '/', 1), ''),
    pt.target
  ) AS hostname,
  COALESCE(tos.os, '—') AS os,
  COALESCE(tp.port_list, '—') AS open_ports,
  CASE
    WHEN pt.sum_critical > 0 THEN 'Critical'
    WHEN pt.sum_high     > 0 THEN 'High'
    WHEN pt.sum_medium   > 0 THEN 'Medium'
    WHEN pt.sum_low      > 0 THEN 'Low'
    ELSE 'Info'
  END AS risk,
  pt.last_scan  AS last_scan,
  pt.created_at AS created_at
FROM per_target pt
LEFT JOIN target_ports tp  ON tp.target  = pt.target
LEFT JOIN target_os    tos ON tos.target = pt.target;

-- -------------------------------------------------------------
-- 10. Grants on all views
-- -------------------------------------------------------------
GRANT SELECT ON
  public.chart_vulns_by_exprt,
  public.chart_findings_by_type,
  public.chart_exploitability_risk,
  public.chart_attack_vector,
  public.chart_exploit_types,
  public.chart_top_vulnerable_products,
  public.scanned_assets
TO anon, authenticated;

COMMIT;

-- =============================================================
-- DONE. All 6 chart views + scanned_assets are live.
-- chart_exploit_types shows data immediately after
--   python3 scripts/sync_exploitdb_to_supabase.py  runs.
-- The other 5 charts need scan_findings + cve_catalog data.
-- =============================================================

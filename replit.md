# Workspace

## Overview

pnpm workspace monorepo using TypeScript. Each package manages its own dependencies.

## Stack

- **Monorepo tool**: pnpm workspaces
- **Node.js version**: 24
- **Package manager**: pnpm
- **TypeScript version**: 5.9
- **API framework**: Express 5
- **Database**: PostgreSQL + Drizzle ORM
- **Validation**: Zod (`zod/v4`), `drizzle-zod`
- **API codegen**: Orval (from OpenAPI spec)
- **Build**: esbuild (CJS bundle)

## Key Commands

- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)
- `pnpm --filter @workspace/api-server run dev` — run API server locally

See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details.

## Assets Dashboard Charts

The Assets Dashboard (`/`) now displays 6 donut charts powered by Supabase views:

| View | Chart |
|------|-------|
| `chart_vulns_by_exprt` | Vulnerabilities by ExPRT rating (Critical/High/Medium/Low) |
| `chart_findings_by_type` | Vulnerabilities by type (Vuln vs Misconf) |
| `chart_exploitability_risk` | Exploitability risk (Weaponized/PoC/Known CVE) |
| `chart_attack_vector` | Attack vector from CVSS v3 (Network/Adjacent/Local/Physical) |
| `chart_exploit_types` | All indexed exploits by type (Remote/Web App/Local Privilege/…) |
| `chart_top_vulnerable_products` | Top-7 vendor+product by distinct CVE count |

**Key files:**
- `artifacts/web-app/src/hooks/useChartView.ts` — Supabase query hook per view
- `artifacts/web-app/src/components/DashboardDonuts.tsx` — 3×2 grid of donuts
- `artifacts/web-app/src/components/DonutChart.tsx` — reusable chart component
- `supabase/migrations/20260501100000_dashboard_chart_views.sql` — run this in Supabase SQL Editor

**Note:** `chart_exploit_types` shows data as soon as `exploits` table has rows (no CVE correlation needed).

## Data Population Scripts

Two scripts populate the Supabase tables that feed the dashboard. Run from any machine (not just Kali):

| Script | Populates | Command |
|--------|-----------|---------|
| `scripts/sync_nvd_to_supabase.py` | `cve_catalog` (CVE severity, CVSS vectors) | `python3 scripts/sync_nvd_to_supabase.py` |
| `scripts/sync_exploitdb_to_supabase.py` | `exploits` (exploit types, CVE links) | `python3 scripts/sync_exploitdb_to_supabase.py` |

**Requirements:** `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` must be in `.env`.

**Difference from Kali scripts:**
- `scripts/download_nvd.py` and `scripts/index_exploitdb.py` → build local SQLite for scan-time matching on Kali
- `scripts/sync_nvd_to_supabase.py` and `scripts/sync_exploitdb_to_supabase.py` → push data directly to Supabase for the dashboard

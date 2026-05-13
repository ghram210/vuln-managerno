-- =============================================================
-- Final Permission Fix: Ensure 'user' role visibility for shared data
-- =============================================================

BEGIN;

-- 1. Ensure user_roles is readable by all authenticated users
-- This allows the has_role function and frontend role checks to work correctly
DROP POLICY IF EXISTS "Users can view own role" ON public.user_roles;
CREATE POLICY "authenticated_select_user_roles" ON public.user_roles
FOR SELECT TO authenticated
USING (true);

-- 2. Ensure all relevant dashboard views and tables have SELECT granted
-- Some views might have been created without explicit grants or with restrictive ones
GRANT SELECT ON ALL TABLES IN SCHEMA public TO authenticated;

-- 3. Double-check RLS on scan_results to ensure it matches the 'user' requirement
-- We want 'user' (Security User) to see ALL scans, but only 'admin' to manage them.
DROP POLICY IF EXISTS "scan_results_select" ON public.scan_results;
CREATE POLICY "scan_results_select_v2" ON public.scan_results
FOR SELECT TO authenticated
USING (
  user_id = auth.uid() OR
  public.has_role(auth.uid(), 'user') OR
  public.has_role(auth.uid(), 'admin')
);

-- 4. Ensure target_report_data view (used by ReportsTab) is also covered
-- If it's a security_invoker = true view, it will inherit RLS from scan_results and findings.
-- If it's security_invoker = false (default), it needs to be redefined or RLS checked.

COMMIT;

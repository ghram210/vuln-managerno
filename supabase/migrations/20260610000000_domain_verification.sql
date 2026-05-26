-- Migration: Domain Verification and Admin update
BEGIN;

-- 1. Create user_domains table
CREATE TABLE IF NOT EXISTS public.user_domains (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  domain TEXT NOT NULL,
  verification_token TEXT NOT NULL,
  is_verified BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  UNIQUE(user_id, domain)
);

-- 2. RLS for user_domains
ALTER TABLE public.user_domains ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users can manage their own domains" ON public.user_domains;
CREATE POLICY "Users can manage their own domains"
  ON public.user_domains FOR ALL
  TO authenticated
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "Admins can view all domains" ON public.user_domains;
CREATE POLICY "Admins can view all domains"
  ON public.user_domains FOR SELECT
  TO authenticated
  USING (public.has_role(auth.uid(), 'admin'));

-- 3. Update handle_new_user trigger to set specific admins
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
    user_full_name text;
    target_role public.app_role := 'user'::public.app_role;
    target_role_label text := 'User';
BEGIN
    BEGIN
        -- A. Extract metadata
        user_full_name := COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.email);

        -- B. Proactive CLEANUP of orphaned records or placeholders by email
        DELETE FROM public.user_roles WHERE user_id IN (
            SELECT id FROM public.admin_users WHERE lower(email) = lower(NEW.email) AND id <> NEW.id
        );
        DELETE FROM public.admin_users WHERE lower(email) = lower(NEW.email) AND id <> NEW.id;

        -- C. Sync Role: Hardcode specific admins
        IF lower(NEW.email) IN ('jehanmoshle@gmail.com', 'gharamrahal6@gmail.com') THEN
            target_role := 'admin'::public.app_role;
            target_role_label := 'Admin';
        END IF;

        -- D. Sync to user_roles
        INSERT INTO public.user_roles (user_id, role)
        VALUES (NEW.id, target_role)
        ON CONFLICT (user_id) DO UPDATE SET role = EXCLUDED.role;

        -- E. Sync to admin_users
        INSERT INTO public.admin_users (id, email, name, role, joined_at)
        VALUES (
            NEW.id,
            NEW.email,
            user_full_name,
            target_role_label,
            NOW()
        )
        ON CONFLICT (id) DO UPDATE SET
            email = EXCLUDED.email,
            name = EXCLUDED.name,
            role = EXCLUDED.role;

    EXCEPTION WHEN OTHERS THEN
        NULL;
    END;

    RETURN NEW;
END;
$$;

-- 4. Update existing users roles based on the new admin list
UPDATE public.user_roles
SET role = 'admin'::public.app_role
WHERE user_id IN (SELECT id FROM auth.users WHERE lower(email) IN ('jehanmoshle@gmail.com', 'gharamrahal6@gmail.com'));

UPDATE public.user_roles
SET role = 'user'::public.app_role
WHERE user_id NOT IN (SELECT id FROM auth.users WHERE lower(email) IN ('jehanmoshle@gmail.com', 'gharamrahal6@gmail.com'));

UPDATE public.admin_users
SET role = 'Admin'
WHERE lower(email) IN ('jehanmoshle@gmail.com', 'gharamrahal6@gmail.com');

UPDATE public.admin_users
SET role = 'User'
WHERE lower(email) NOT IN ('jehanmoshle@gmail.com', 'gharamrahal6@gmail.com');

-- 5. Update scan_results RLS to allow users to create scans and Admins to see everything
DROP POLICY IF EXISTS "scan_results_manage" ON public.scan_results;
DROP POLICY IF EXISTS "scan_results_insert" ON public.scan_results;
CREATE POLICY "scan_results_insert" ON public.scan_results
FOR INSERT TO authenticated
WITH CHECK (user_id = auth.uid());

DROP POLICY IF EXISTS "scan_results_update_delete" ON public.scan_results;
CREATE POLICY "scan_results_update_delete" ON public.scan_results
FOR ALL TO authenticated
USING (user_id = auth.uid() OR public.has_role(auth.uid(), 'admin'))
WITH CHECK (user_id = auth.uid() OR public.has_role(auth.uid(), 'admin'));

DROP POLICY IF EXISTS "scan_results_select" ON public.scan_results;
CREATE POLICY "scan_results_select" ON public.scan_results
FOR SELECT TO authenticated
USING (
  user_id = auth.uid() OR
  public.has_role(auth.uid(), 'admin') OR
  user_id = public.get_inviter_id(auth.uid())
);

COMMIT;

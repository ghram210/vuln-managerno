-- ========================================================
-- ULTIMATE User Management and Security Fix (Consolidated v6)
-- ========================================================
-- This migration ensures that user registration NEVER fails due to
-- synchronization issues and enforces strict security policies.
-- It addresses:
-- 1. SECURITY: Defaults all signups to 'User' unless already 'Admin'.
-- 2. STABILITY: Uses EXCEPTION handling to prevent blocking signups.
-- 3. TYPE SAFETY: Correctly handles UUID vs TEXT (Fixes Error 42804).
-- 4. PRESERVATION: Keeps existing Admin accounts safe.
-- 5. CLEANUP: Demotes specific accidental admins.

-- 1. Prerequisites (Types and Functions)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'app_role') THEN
        CREATE TYPE public.app_role AS ENUM ('admin', 'user');
    END IF;
END $$;

-- 2. Clean up specific accidental admins (Security Cleanup)
DO $$
BEGIN
    -- List of emails to demote to 'User'
    UPDATE public.user_roles
    SET role = 'user'::public.app_role
    WHERE user_id IN (
        SELECT id FROM auth.users
        WHERE lower(email) IN ('rhallhanin@gmail.com', 'gharamrahal6@gmil.com', 'gharamrahal6@gmail.com')
    );

    UPDATE public.admin_users
    SET role = 'User'
    WHERE lower(email) IN ('rhallhanin@gmail.com', 'gharamrahal6@gmil.com', 'gharamrahal6@gmail.com');
END $$;

-- 3. Case-insensitive has_role function (handles ENUM casting correctly)
CREATE OR REPLACE FUNCTION public.has_role(_user_id uuid, _role text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.user_roles
    WHERE user_id = _user_id AND lower(role::text) = lower(_role)
  );
$$;

-- 4. BULLETPROOF Trigger Function for ANY new user signup
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
    existing_role text;
    user_full_name text;
BEGIN
    -- A. Extract metadata
    user_full_name := COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.email);

    -- B. Check if this email was ALREADY an Admin in our system
    -- This ensures legitimate admins don't lose access if they re-register.
    SELECT role INTO existing_role
    FROM public.admin_users
    WHERE lower(email) = lower(NEW.email)
    ORDER BY CASE WHEN lower(role) = 'admin' THEN 1 ELSE 2 END
    LIMIT 1;

    -- C. CLEANUP Orphaned records
    -- We delete by email to prevent "duplicate key" errors on email unique constraint.
    -- Crucial: Delete from user_roles first to satisfy potential FKs.
    DELETE FROM public.user_roles WHERE user_id IN (
        SELECT id FROM public.admin_users WHERE lower(email) = lower(NEW.email) AND id <> NEW.id
    );
    DELETE FROM public.admin_users WHERE lower(email) = lower(NEW.email) AND id <> NEW.id;

    -- D. SYNC to user_roles
    -- Native UUID (NEW.id) is used. Role is preserved or defaulted to 'user'.
    INSERT INTO public.user_roles (user_id, role)
    VALUES (
        NEW.id,
        CASE WHEN lower(existing_role) = 'admin' THEN 'admin'::public.app_role ELSE 'user'::public.app_role END
    )
    ON CONFLICT (user_id) DO UPDATE SET
        role = EXCLUDED.role;

    -- E. SYNC to admin_users (UI table)
    INSERT INTO public.admin_users (id, email, name, role, joined_at)
    VALUES (
        NEW.id,
        NEW.email,
        user_full_name,
        CASE WHEN lower(existing_role) = 'admin' THEN 'Admin' ELSE 'User' END,
        NOW()
    )
    ON CONFLICT (id) DO UPDATE SET
        email = EXCLUDED.email,
        name = EXCLUDED.name,
        role = EXCLUDED.role;

    RETURN NEW;
EXCEPTION WHEN OTHERS THEN
    -- Ensure user creation in auth.users is never blocked.
    RETURN NEW;
END;
$$;

-- 5. Re-enable the trigger
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
DROP TRIGGER IF EXISTS on_auth_user_created_sync ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- 6. Strict Invitation Fulfillment
CREATE OR REPLACE FUNCTION public.use_invitation_token(token_param text, user_id_param uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  inv RECORD;
  user_email text;
BEGIN
  -- Get the registering user's email
  SELECT email INTO user_email FROM auth.users WHERE id = user_id_param;

  -- Validate the invitation token
  SELECT * INTO inv
  FROM public.invitation_links
  WHERE token = token_param
    AND is_active = true
    AND (expires_at IS NULL OR expires_at > now())
    AND (max_uses IS NULL OR uses_count < max_uses);

  IF inv IS NULL THEN RETURN false; END IF;

  -- Enforce email match if the invitation was targeted
  IF inv.email IS NOT NULL AND lower(inv.email) <> lower(user_email) THEN
    RETURN false;
  END IF;

  -- Record usage
  INSERT INTO public.invitation_usages (invitation_id, user_id)
  VALUES (inv.id, user_id_param)
  ON CONFLICT DO NOTHING;

  UPDATE public.invitation_links SET uses_count = uses_count + 1 WHERE id = inv.id;

  -- Assign 'user' role ONLY if they aren't already an admin.
  IF NOT EXISTS (SELECT 1 FROM public.user_roles WHERE user_id = user_id_param AND lower(role::text) = 'admin') THEN
      INSERT INTO public.user_roles (user_id, role)
      VALUES (user_id_param, 'user'::public.app_role)
      ON CONFLICT (user_id) DO UPDATE SET role = 'user'::public.app_role;

      UPDATE public.admin_users SET role = 'User' WHERE id = user_id_param;
  END IF;

  RETURN true;
END;
$$;

-- 7. Tighten RLS for scan_results (Security Fix)
DROP POLICY IF EXISTS "Authenticated can view scan_results" ON public.scan_results;
DROP POLICY IF EXISTS "Users can view own scan_results" ON public.scan_results;
CREATE POLICY "Users can view own scan_results"
  ON public.scan_results FOR SELECT TO authenticated
  USING (auth.uid() = user_id OR public.has_role(auth.uid(), 'admin'));

-- 8. Standardization and Duplication Cleanup
UPDATE public.admin_users SET role = 'Admin' WHERE lower(role) = 'admin';
UPDATE public.admin_users SET role = 'User' WHERE lower(role) = 'user' OR role IS NULL;

-- Remove duplicate emails if any remain (keeps Admin, then newest)
DELETE FROM public.admin_users a
WHERE a.id IN (
    SELECT id FROM (
        SELECT id, row_number() OVER (
            PARTITION BY lower(email)
            ORDER BY
                CASE WHEN role = 'Admin' THEN 1 ELSE 2 END,
                joined_at DESC
        ) as rn
        FROM public.admin_users
    ) t WHERE t.rn > 1
);

-- Ensure Unique Email Constraint
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relname = 'admin_users_email_key'
        AND n.nspname = 'public'
    ) THEN
        ALTER TABLE public.admin_users ADD CONSTRAINT admin_users_email_key UNIQUE (email);
    END IF;
END $$;

-- 9. Backfill Missing Users
INSERT INTO public.user_roles (user_id, role)
SELECT id, 'user'::public.app_role FROM auth.users
ON CONFLICT (user_id) DO NOTHING;

INSERT INTO public.admin_users (id, email, name, role, joined_at)
SELECT
    u.id,
    u.email,
    COALESCE(u.raw_user_meta_data->>'full_name', u.email),
    'User',
    u.created_at
FROM auth.users u
WHERE NOT EXISTS (
    SELECT 1 FROM public.admin_users a
    WHERE a.id = u.id OR lower(a.email) = lower(u.email)
)
ON CONFLICT DO NOTHING;

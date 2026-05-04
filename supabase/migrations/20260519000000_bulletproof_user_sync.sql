-- ========================================================
-- BULLETPROOF User Management and Security Fix (v4)
-- ========================================================
-- This migration addresses:
-- 1. "Invalid login credentials" after registration by ensuring roles are assigned correctly.
-- 2. Data leakage by tightening scan_results RLS policies.
-- 3. Registration failures by robustly cleaning up orphaned email records.
-- 4. Case-insensitivity and strict type handling for UUIDs and ENUMs.

-- 1. Ensure the app_role ENUM exists if it's being used by the system
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'app_role') THEN
        CREATE TYPE public.app_role AS ENUM ('admin', 'user');
    END IF;
END $$;

-- 2. Standardize existing roles and clean up potential duplicates
DO $$
BEGIN
    -- Standardize roles to capitalized for UI in admin_users (TEXT)
    UPDATE public.admin_users SET role = 'Admin' WHERE lower(role) = 'admin';
    UPDATE public.admin_users SET role = 'User' WHERE lower(role) = 'user' OR role IS NULL;

    -- Standardize user_roles (Handles potential ENUM or TEXT)
    -- We use explicit casting to text for lower() function compatibility
    UPDATE public.user_roles SET role = 'admin'::public.app_role WHERE lower(role::text) = 'admin';
    UPDATE public.user_roles SET role = 'user'::public.app_role WHERE lower(role::text) = 'user' OR role IS NULL;

    -- Clean up duplicate emails in admin_users (keep Admin if exists, else newest)
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

    -- Ensure unique constraint on email for admin_users
    IF NOT EXISTS (
        SELECT 1 FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relname = 'admin_users_email_key'
        AND n.nspname = 'public'
    ) THEN
        ALTER TABLE public.admin_users ADD CONSTRAINT admin_users_email_key UNIQUE (email);
    END IF;
END $$;

-- 3. Case-insensitive has_role function (handles ENUM casting)
CREATE OR REPLACE FUNCTION public.has_role(_user_id uuid, _role text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.user_roles
    WHERE user_id = _user_id AND lower(role::text) = lower(_role)
  );
$$;

-- 4. Robust Trigger Function for new users
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
    target_role text;
    user_full_name text;
BEGIN
    -- A. Extract metadata
    user_full_name := COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.email);

    -- B. Determine target role: Check if this email was pre-registered as Admin in admin_users
    SELECT role INTO target_role
    FROM public.admin_users
    WHERE lower(email) = lower(NEW.email)
    ORDER BY CASE WHEN lower(role) = 'admin' THEN 1 ELSE 2 END
    LIMIT 1;

    -- Default to 'User'
    target_role := COALESCE(target_role, 'User');

    -- C. CLEANUP orphaned records with same email but different ID
    -- We ensure all ID comparisons use the native UUID type
    DELETE FROM public.user_roles WHERE user_id IN (
        SELECT id FROM public.admin_users WHERE lower(email) = lower(NEW.email) AND id <> NEW.id
    );
    DELETE FROM public.admin_users WHERE lower(email) = lower(NEW.email) AND id <> NEW.id;

    -- D. SYNC: user_roles (lowercase, cast to ENUM if needed)
    INSERT INTO public.user_roles (user_id, role)
    VALUES (NEW.id, lower(target_role)::public.app_role)
    ON CONFLICT (user_id) DO UPDATE SET role = EXCLUDED.role;

    -- E. SYNC: admin_users (capitalized)
    INSERT INTO public.admin_users (id, email, name, role, joined_at)
    VALUES (
        NEW.id,
        NEW.email,
        user_full_name,
        CASE WHEN lower(target_role) = 'admin' THEN 'Admin' ELSE 'User' END,
        NOW()
    )
    ON CONFLICT (id) DO UPDATE SET
        email = EXCLUDED.email,
        name = EXCLUDED.name,
        role = EXCLUDED.role;

    RETURN NEW;
EXCEPTION WHEN OTHERS THEN
    -- Prevent blocking auth even on sync failure
    RETURN NEW;
END;
$$;

-- 5. Re-enable the trigger
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- 6. Tighten RLS for scan_results (Security Fix)
DROP POLICY IF EXISTS "Authenticated can view scan_results" ON public.scan_results;
CREATE POLICY "Users can view own scan_results"
  ON public.scan_results FOR SELECT TO authenticated
  USING (auth.uid() = user_id OR public.has_role(auth.uid(), 'admin'));

-- 7. Backfill missing users
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

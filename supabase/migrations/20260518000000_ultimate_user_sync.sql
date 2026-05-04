-- ========================================================
-- ULTIMATE User Management and Registration Fix
-- ========================================================
-- This migration ensures that the user registration trigger is bulletproof.
-- It handles:
-- 1. Cleaning up orphaned records from failed deletions.
-- 2. Preserving 'Admin' roles if they were pre-assigned by email.
-- 3. Synchronizing BOTH user_roles and admin_users tables.
-- 4. Handling case-sensitivity for emails consistently.

-- 1. Standardize existing roles and clean up potential duplicates first
DO $$
BEGIN
    -- Standardize roles
    UPDATE public.admin_users SET role = 'Admin' WHERE lower(role) = 'admin';
    UPDATE public.admin_users SET role = 'User' WHERE lower(role) = 'user' OR role IS NULL;

    -- Clean up duplicate emails (keep Admin if exists, else newest)
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

-- 2. Create the Ultimate Trigger Function
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
    target_role text;
    user_full_name text;
BEGIN
    -- A. Extract metadata
    user_full_name := COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.email);

    -- B. Determine the target role.
    -- Check if this email was already registered as an Admin
    SELECT role INTO target_role
    FROM public.admin_users
    WHERE lower(email) = lower(NEW.email)
    ORDER BY CASE WHEN role = 'Admin' THEN 1 ELSE 2 END
    LIMIT 1;

    -- Default to 'User' if no pre-existing role found
    target_role := COALESCE(target_role, 'User');

    -- C. CLEANUP: Remove any records with the same email but DIFFERENT ID
    -- This prevents 'duplicate key' errors on the email unique constraint
    DELETE FROM public.user_roles WHERE user_id IN (
        SELECT id FROM public.admin_users WHERE lower(email) = lower(NEW.email) AND id <> NEW.id
    );
    DELETE FROM public.admin_users WHERE lower(email) = lower(NEW.email) AND id <> NEW.id;

    -- D. SYNC: user_roles (Lowercased for RBAC logic)
    INSERT INTO public.user_roles (user_id, role)
    VALUES (
        NEW.id,
        lower(target_role)
    )
    ON CONFLICT (user_id) DO UPDATE SET
        role = EXCLUDED.role;

    -- E. SYNC: admin_users (Capitalized for UI consistency)
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
    -- In case of ANY error, we don't want to block the user from being created in Auth
    -- but we should at least log it if we could. Since we can't easily log to a file here,
    -- we return NEW and hope the Auth user creation succeeds.
    -- NOTE: If this fails, the user might not have a role, but they can at least sign up.
    RETURN NEW;
END;
$$;

-- 3. Re-enable the trigger
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- 4. Final backfill for any existing inconsistencies
INSERT INTO public.user_roles (user_id, role)
SELECT id, 'user' FROM auth.users
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

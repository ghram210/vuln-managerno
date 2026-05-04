-- ========================================================
-- Robust User Management and Registration Fix
-- ========================================================

-- 1. Standardize roles to capitalized versions for UI consistency
UPDATE public.admin_users SET role = 'Admin' WHERE lower(role) = 'admin';
UPDATE public.admin_users SET role = 'User' WHERE lower(role) = 'user' OR role IS NULL;

-- 2. Clean up duplicate emails in admin_users
-- Keeps the 'Admin' record if exists, otherwise the most recently joined entry
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

-- 3. Ensure unique constraint on email exists
-- This prevents future duplicates and is required for some ON CONFLICT clauses
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

-- 4. Final Robust Trigger Function
-- This version preserves existing Admin roles and handles email/ID conflicts.
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
    target_role text;
BEGIN
    -- A. Determine the target role.
    -- If a user with this email already exists in admin_users, preserve their role.
    -- This handles cases where an Admin was added manually before they signed up.
    SELECT role INTO target_role
    FROM public.admin_users
    WHERE lower(email) = lower(NEW.email)
    LIMIT 1;

    -- Default to 'User' if not found
    target_role := COALESCE(target_role, 'User');

    -- B. Ensure user has the correct role in user_roles
    -- user_roles table expects lowercase 'admin' or 'user'
    INSERT INTO public.user_roles (user_id, role)
    VALUES (
        NEW.id,
        CASE WHEN lower(target_role) = 'admin' THEN 'admin' ELSE 'user' END
    )
    ON CONFLICT (user_id) DO UPDATE SET
        role = EXCLUDED.role;

    -- C. Sync user to admin_users
    -- First, remove any record that has the same email but different ID to prevent unique violations
    DELETE FROM public.admin_users WHERE lower(email) = lower(NEW.email) AND id <> NEW.id;

    -- Now perform the insert or update
    INSERT INTO public.admin_users (id, email, name, role, joined_at)
    VALUES (
        NEW.id,
        NEW.email,
        COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.email),
        target_role,
        NOW()
    )
    ON CONFLICT (id) DO UPDATE SET
        email = EXCLUDED.email,
        name = EXCLUDED.name,
        role = EXCLUDED.role;

    RETURN NEW;
END;
$$;

-- 5. Re-enable the trigger
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- 6. Backfill missing users from auth.users to user_roles and admin_users
-- This ensures that "missing" users are synchronized once this migration runs.

-- Sync to user_roles
INSERT INTO public.user_roles (user_id, role)
SELECT id, 'user' FROM auth.users
ON CONFLICT (user_id) DO NOTHING;

-- Sync to admin_users (only if both id and email are not already present)
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

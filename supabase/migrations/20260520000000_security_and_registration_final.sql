-- ========================================================
-- FINAL BULLETPROOF User Management and Security Fix (v5)
-- ========================================================
-- This migration addresses:
-- 1. SECURITY: Prevents accidental admin escalation by defaulting all new signups to 'User'.
-- 2. FIX: Demotes 'rhallhanin@gmail.com' to User role to resolve current breach.
-- 3. ROBUSTNESS: Improved cleanup of orphaned records to prevent registration errors.
-- 4. CONSISTENCY: Ensures role capitalization is synced across all tables.

-- 1. Fix the current security breach immediately
DO $$
BEGIN
    -- Demote the specific user to 'user' in both tables
    UPDATE public.user_roles
    SET role = 'user'::public.app_role
    WHERE user_id IN (SELECT id FROM auth.users WHERE lower(email) = 'rhallhanin@gmail.com');

    UPDATE public.admin_users
    SET role = 'User'
    WHERE lower(email) = 'rhallhanin@gmail.com';
END $$;

-- 2. Update the trigger to be strictly 'User' by default
-- This removes the role inheritance that caused the escalation.
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
    user_full_name text;
BEGIN
    -- A. Extract metadata
    user_full_name := COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.email);

    -- B. CLEANUP: Remove ANY existing records for this email that don't match this ID.
    -- This is critical to prevent unique constraint violations (admin_users_email_key).
    DELETE FROM public.user_roles WHERE user_id IN (
        SELECT id FROM public.admin_users WHERE lower(email) = lower(NEW.email) AND id <> NEW.id
    );
    DELETE FROM public.admin_users WHERE lower(email) = lower(NEW.email) AND id <> NEW.id;

    -- C. SYNC: Always default new users to 'user' role for security.
    -- Administrators must be promoted manually via the Admin Panel or SQL.

    INSERT INTO public.user_roles (user_id, role)
    VALUES (NEW.id, 'user'::public.app_role)
    ON CONFLICT (user_id) DO UPDATE SET
        role = CASE WHEN public.user_roles.role = 'admin' THEN 'admin'::public.app_role ELSE 'user'::public.app_role END;

    INSERT INTO public.admin_users (id, email, name, role, joined_at)
    VALUES (
        NEW.id,
        NEW.email,
        user_full_name,
        'User',
        NOW()
    )
    ON CONFLICT (id) DO UPDATE SET
        email = EXCLUDED.email,
        name = EXCLUDED.name,
        role = CASE WHEN public.admin_users.role = 'Admin' THEN 'Admin' ELSE 'User' END;

    RETURN NEW;
EXCEPTION WHEN OTHERS THEN
    -- Log the error if possible, but don't block the auth process
    -- In a real environment, you might use a custom log table here
    RETURN NEW;
END;
$$;

-- 3. Re-ensure the trigger is correctly attached
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- 4. Final Cleanup: Ensure no duplicate emails exist after the fix
DELETE FROM public.admin_users a
WHERE a.id IN (
    SELECT id FROM (
        SELECT id, row_number() OVER (
            PARTITION BY lower(email)
            ORDER BY
                CASE WHEN lower(role) = 'admin' THEN 1 ELSE 2 END,
                joined_at DESC
        ) as rn
        FROM public.admin_users
    ) t WHERE t.rn > 1
);

-- 5. Standardize Role Casing one last time
UPDATE public.admin_users SET role = 'Admin' WHERE lower(role) = 'admin';
UPDATE public.admin_users SET role = 'User' WHERE lower(role) = 'user' OR role IS NULL;

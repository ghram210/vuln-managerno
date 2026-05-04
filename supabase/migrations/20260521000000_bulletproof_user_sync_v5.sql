-- ========================================================
-- BULLETPROOF User Management and Security Fix (v5)
-- ========================================================

-- 1. Fix the specific user rhallhanin@gmail.com
-- This user was incorrectly registered as Admin.
DO $$
BEGIN
    -- Update user_roles to 'user'
    -- We use the user_id from admin_users to match
    UPDATE public.user_roles
    SET role = 'user'::public.app_role
    WHERE user_id IN (SELECT id FROM public.admin_users WHERE lower(email) = lower('rhallhanin@gmail.com'));

    -- Update admin_users to 'User'
    UPDATE public.admin_users
    SET role = 'User'
    WHERE lower(email) = lower('rhallhanin@gmail.com');
END $$;

-- 2. Update the handle_new_user function to be more restrictive
-- It should ALWAYS default to 'User' role for new auth registrations.
-- Administrative roles should be assigned manually or via a separate flow
-- to prevent accidental privilege escalation from orphaned/stale records.
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
    user_full_name text;
BEGIN
    -- A. Extract metadata
    user_full_name := COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.email);

    -- B. CLEANUP orphaned records with same email but different ID
    -- This ensures the unique constraint on email in admin_users isn't violated
    -- and removes any stale permissions associated with the email.
    DELETE FROM public.user_roles WHERE user_id IN (
        SELECT id FROM public.admin_users WHERE lower(email) = lower(NEW.email) AND id <> NEW.id
    );
    DELETE FROM public.admin_users WHERE lower(email) = lower(NEW.email) AND id <> NEW.id;

    -- C. SYNC: user_roles (Strictly 'user' for new registrations)
    INSERT INTO public.user_roles (user_id, role)
    VALUES (NEW.id, 'user'::public.app_role)
    ON CONFLICT (user_id) DO UPDATE SET role = 'user'::public.app_role;

    -- D. SYNC: admin_users (Strictly 'User' for new registrations)
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
        role = 'User';

    RETURN NEW;
EXCEPTION WHEN OTHERS THEN
    -- Prevent blocking authentication if sync fails
    RETURN NEW;
END;
$$;

-- 3. Ensure the trigger is active
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

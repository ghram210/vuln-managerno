-- ========================================================
-- Fix User Registration and Trigger Robustness
-- ========================================================

-- 1. Ensure admin_users has a unique constraint on email if not already there
-- This is needed for the ON CONFLICT clause to work on email as well.
DO $$
BEGIN
    -- Check if the constraint or index with this name already exists
    IF NOT EXISTS (
        SELECT 1 FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relname = 'admin_users_email_key'
        AND n.nspname = 'public'
    ) THEN
        ALTER TABLE public.admin_users ADD CONSTRAINT admin_users_email_key UNIQUE (email);
    END IF;
EXCEPTION
    WHEN duplicate_table OR duplicate_object THEN
        -- Handle case where it might have been created concurrently or exists as different object type
        NULL;
END $$;

-- 2. Update the handle_new_user function to be extremely robust
-- It should handle conflicts on ID and Email separately to prevent registration failures.
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
    existing_id uuid;
BEGIN
    -- A. Ensure user has 'user' role in user_roles
    INSERT INTO public.user_roles (user_id, role)
    VALUES (NEW.id, 'user')
    ON CONFLICT (user_id) DO NOTHING;

    -- B. Sync user to admin_users
    -- First, check if a user with this email already exists but with a different ID
    SELECT id INTO existing_id FROM public.admin_users WHERE lower(email) = lower(NEW.email) LIMIT 1;

    IF existing_id IS NOT NULL AND existing_id <> NEW.id THEN
        -- Update the existing record to match the new auth ID
        UPDATE public.admin_users
        SET
            id = NEW.id,
            name = COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.email),
            joined_at = NOW()
        WHERE email = NEW.email;
    ELSE
        -- Standard insert or update on ID conflict
        INSERT INTO public.admin_users (id, email, name, role, joined_at)
        VALUES (
            NEW.id,
            NEW.email,
            COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.email),
            'User',
            NOW()
        )
        ON CONFLICT (id) DO UPDATE SET
            email = EXCLUDED.email,
            name = EXCLUDED.name;
    END IF;

    RETURN NEW;
END;
$$;

-- 3. Re-enable the trigger
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

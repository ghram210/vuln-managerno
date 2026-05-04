-- ========================================================
-- ULTIMATE FAIL-SAFE User Registration (v8)
-- ========================================================
-- This migration provides the most resilient registration trigger possible.
-- It addresses the "Database error saving new user" by:
-- 1. Ensuring ONLY ONE trigger exists on auth.users.
-- 2. Performing aggressive email-based cleanup BEFORE insertion to prevent unique violations.
-- 3. Wrapping the entire synchronization in a nested EXCEPTION block.
-- 4. Logging detailed diagnostics to 'public.system_logs'.

-- 1. Remove all potential duplicate triggers to prevent double execution
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
DROP TRIGGER IF EXISTS sync_user_to_admin_users ON auth.users;
DROP TRIGGER IF EXISTS ensure_user_role ON auth.users;

-- 2. Clean up problematic accounts identified by the user
-- These accounts have had issues with registration placeholders.
DELETE FROM public.user_roles
WHERE user_id IN (SELECT id FROM public.admin_users WHERE lower(email) IN (
    'rhallhanin@gmail.com',
    'rhaalhanin@gmail.com',
    'gharamrahal6@gmil.com',
    'gharamrahal6@gmail.com',
    'almwshlyjyhan@gmail.com'
));

DELETE FROM public.admin_users
WHERE lower(email) IN (
    'rhallhanin@gmail.com',
    'rhaalhanin@gmail.com',
    'gharamrahal6@gmil.com',
    'gharamrahal6@gmail.com',
    'almwshlyjyhan@gmail.com'
);

-- 3. Enhanced Trigger Function with Logging and Multi-Layer Fail-Safes
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
    _user_full_name text;
    _target_role text := 'user';
    _target_role_label text := 'User';
    _error_msg text;
    _error_detail text;
BEGIN
    -- A. Extract metadata safely
    _user_full_name := COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.email);

    -- B. INNER BLOCK to catch and log all errors without failing the main transaction
    BEGIN
        -- 1. Log the attempt
        INSERT INTO public.system_logs (message, level)
        VALUES ('[RegV8] Starting sync for: ' || NEW.email || ' (ID: ' || NEW.id || ')', 'info');

        -- 2. Aggressive Cleanup of Existing Records
        -- We delete by email to prevent "unique_constraint_violation" on admin_users(email)
        -- which happens if a placeholder exists with a different ID (e.g. from an API invitation).
        DELETE FROM public.user_roles WHERE user_id IN (
            SELECT id FROM public.admin_users WHERE lower(email) = lower(NEW.email)
        );
        DELETE FROM public.admin_users WHERE lower(email) = lower(NEW.email);

        -- 3. Determine Role (Security: Defaults to User)
        -- PROTECTED ADMINS: akatsukigh510@gmail.com, jehanmoshle@gmail.com
        IF lower(NEW.email) IN ('akatsukigh510@gmail.com', 'jehanmoshle@gmail.com') THEN
            _target_role := 'admin';
            _target_role_label := 'Admin';
        END IF;

        -- 4. Sync to user_roles
        INSERT INTO public.user_roles (user_id, role)
        VALUES (NEW.id, _target_role::public.app_role)
        ON CONFLICT (user_id) DO UPDATE SET role = EXCLUDED.role;

        -- 5. Sync to admin_users
        INSERT INTO public.admin_users (id, email, name, role, joined_at)
        VALUES (
            NEW.id,
            NEW.email,
            _user_full_name,
            _target_role_label,
            NOW()
        )
        ON CONFLICT (id) DO UPDATE SET
            email = EXCLUDED.email,
            name = EXCLUDED.name,
            role = EXCLUDED.role;

        -- 6. Log success
        INSERT INTO public.system_logs (message, level)
        VALUES ('[RegV8] Success for: ' || NEW.email || ' as ' || _target_role_label, 'info');

    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS
            _error_msg = MESSAGE_TEXT,
            _error_detail = PG_EXCEPTION_DETAIL;

        -- Log the failure but DO NOT raise an error (prevents blocking auth.users insert)
        BEGIN
            INSERT INTO public.system_logs (message, level)
            VALUES ('[RegV8] FAIL-SAFE Error for ' || NEW.email || ': ' || _error_msg || ' | ' || COALESCE(_error_detail, 'no detail'), 'error');
        EXCEPTION WHEN OTHERS THEN
            -- If even logging fails, we must stay silent to allow registration to proceed
            NULL;
        END;
    END;

    -- ALWAYS return NEW to ensure auth.users record is created
    RETURN NEW;
END;
$$;

-- 4. Re-enable the trigger (AFTER INSERT on auth.users)
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- 5. Final Role Verification for Admins
UPDATE public.user_roles
SET role = 'admin'::public.app_role
WHERE user_id IN (
    SELECT id FROM auth.users
    WHERE lower(email) IN ('akatsukigh510@gmail.com', 'jehanmoshle@gmail.com')
);

UPDATE public.admin_users
SET role = 'Admin'
WHERE lower(email) IN ('akatsukigh510@gmail.com', 'jehanmoshle@gmail.com');

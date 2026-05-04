-- ========================================================
-- ULTIMATE USER MANAGEMENT FINAL CONSOLIDATION (v10)
-- ========================================================
-- This migration provides the definitive user management and security setup.
-- It addresses the "Database error saving new user" by:
-- 1. DROPPING EVERY SINGLE POSSIBLE TRIGGER to ensure a clean slate.
-- 2. Providing a FAIL-PROOF trigger that handles placeholder adoption and whitelisting.
-- 3. Explicitly demoting accidental admins identified by the user.
-- 4. Ensuring consistent email normalization (trim/lower) and role casing.

-- 1. CRITICAL: DROP ALL POTENTIAL TRIGGERS
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
DROP TRIGGER IF EXISTS sync_user_to_admin_users ON auth.users;
DROP TRIGGER IF EXISTS ensure_user_role ON auth.users;
DROP TRIGGER IF EXISTS sync_new_user_trigger ON auth.users;
DROP TRIGGER IF EXISTS trigger_sync_new_user ON auth.users;
DROP TRIGGER IF EXISTS on_auth_user_signup ON auth.users;
DROP TRIGGER IF EXISTS handle_new_user_trigger ON auth.users;

-- 2. ENSURE TYPES AND CONSTRAINTS
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'app_role') THEN
        CREATE TYPE public.app_role AS ENUM ('admin', 'user');
    END IF;
END $$;

-- 3. CLEAN UP ACCIDENTAL ADMINS
-- Explicitly demote users identified by the user as accidentally granted admin status.
DO $$
DECLARE
    _emails text[] := ARRAY[
        'rhallhanin@gmail.com',
        'gharamrahal6@gmil.com',
        'gharamrahal6@gmail.com',
        'rhaalhanin@gmail.com',
        'almwshlyjyhan@gmail.com'
    ];
BEGIN
    -- Update roles to 'user' for these emails
    UPDATE public.user_roles
    SET role = 'user'::public.app_role
    WHERE user_id IN (SELECT id FROM auth.users WHERE trim(lower(email)) = ANY(_emails));

    UPDATE public.admin_users
    SET role = 'User'
    WHERE trim(lower(email)) = ANY(_emails);
END $$;

-- 4. RESILIENT TRIGGER FUNCTION
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
    _user_full_name text;
    _target_role text := 'user';
    _target_role_label text := 'User';
    _clean_email text;
BEGIN
    -- OUTER FAIL-SAFE to ensure registration in auth.users NEVER fails
    BEGIN
        _clean_email := trim(lower(NEW.email));
        _user_full_name := COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.email);

        -- A. Role Whitelisting (ONLY these emails can ever be Admin via trigger)
        IF _clean_email IN ('akatsukigh510@gmail.com', 'jehanmoshle@gmail.com') THEN
            _target_role := 'admin';
            _target_role_label := 'Admin';
        END IF;

        -- B. ADOPTION LOGIC
        -- Delete any existing placeholder/orphan record for this email that has a DIFFERENT ID.
        -- This is critical for adopting invitation placeholders created with random UUIDs.
        DELETE FROM public.user_roles WHERE user_id IN (
            SELECT id FROM public.admin_users WHERE trim(lower(email)) = _clean_email AND id <> NEW.id
        );
        DELETE FROM public.admin_users WHERE trim(lower(email)) = _clean_email AND id <> NEW.id;

        -- C. UPSERT user_roles
        INSERT INTO public.user_roles (user_id, role)
        VALUES (NEW.id, _target_role::public.app_role)
        ON CONFLICT (user_id) DO UPDATE SET role = EXCLUDED.role;

        -- D. UPSERT admin_users
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

    EXCEPTION WHEN OTHERS THEN
        -- Log error to system_logs so we can diagnose without blocking the user
        BEGIN
            INSERT INTO public.system_logs (message, level)
            VALUES ('Registration trigger error for ' || COALESCE(NEW.email, 'unknown') || ': ' || SQLERRM, 'error');
        EXCEPTION WHEN OTHERS THEN
            NULL; -- Ignore logging failures
        END;
        RETURN NEW;
    END;

    RETURN NEW;
END;
$$;

-- 5. RE-ATTACH TRIGGER
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- 6. REFINED INVITATION FULFILLMENT
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
  IF inv.email IS NOT NULL AND trim(lower(inv.email)) <> trim(lower(user_email)) THEN
    RETURN false;
  END IF;

  -- Record usage
  INSERT INTO public.invitation_usages (invitation_id, user_id)
  VALUES (inv.id, user_id_param)
  ON CONFLICT DO NOTHING;

  UPDATE public.invitation_links SET uses_count = uses_count + 1 WHERE id = inv.id;

  -- FORCE 'user' role for invited users (extra safety)
  UPDATE public.user_roles SET role = 'user'::public.app_role WHERE user_id = user_id_param;
  UPDATE public.admin_users SET role = 'User' WHERE id = user_id_param;

  RETURN true;
END;
$$;

-- 7. STANDARDIZATION & BACKFILL
UPDATE public.admin_users SET role = 'Admin' WHERE lower(role) = 'admin';
UPDATE public.admin_users SET role = 'User' WHERE lower(role) = 'user' OR role IS NULL;

-- Sync any missing users to user_roles
INSERT INTO public.user_roles (user_id, role)
SELECT id, 'user'::public.app_role FROM auth.users
ON CONFLICT (user_id) DO NOTHING;

-- Sync any missing users to admin_users
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
    WHERE a.id = u.id OR lower(trim(a.email)) = lower(trim(u.email))
)
ON CONFLICT DO NOTHING;

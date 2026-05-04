-- ========================================================
-- ULTIMATE USER MANAGEMENT FINAL CONSOLIDATION (v10) - BULLETPROOF
-- ========================================================
-- This migration provides the DEFINITIVE user management and security setup.

-- 1. CRITICAL: CLEAR ALL TRIGGERS ON auth.users
DO $$
DECLARE
    _trig RECORD;
BEGIN
    FOR _trig IN (
        SELECT trigger_name
        FROM information_schema.triggers
        WHERE event_object_schema = 'auth'
          AND event_object_table = 'users'
    ) LOOP
        EXECUTE 'DROP TRIGGER IF EXISTS ' || quote_ident(_trig.trigger_name) || ' ON auth.users';
    END LOOP;
END $$;

-- 2. ENSURE TYPES AND TABLES EXIST
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'app_role') THEN
        CREATE TYPE public.app_role AS ENUM ('admin', 'user');
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS public.user_roles (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL UNIQUE,
  role public.app_role NOT NULL DEFAULT 'user',
  created_at timestamp with time zone NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.admin_users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text,
  email text NOT NULL,
  role text NOT NULL DEFAULT 'User',
  joined_at timestamp with time zone NOT NULL DEFAULT now()
);

-- Fix table structure to ensure UUIDs are used
DO $$
BEGIN
    IF (SELECT data_type FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'admin_users' AND column_name = 'id') = 'text' THEN
        ALTER TABLE public.admin_users ALTER COLUMN id TYPE uuid USING id::uuid;
    END IF;
    IF (SELECT data_type FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'user_roles' AND column_name = 'user_id') = 'text' THEN
        ALTER TABLE public.user_roles ALTER COLUMN user_id TYPE uuid USING user_id::uuid;
    END IF;
END $$;

-- Ensure unique constraint on admin_users(email) - FIXED VERSION
DO $$
BEGIN
    -- 1. Drop existing constraint/index if it exists to avoid "relation already exists" error
    ALTER TABLE public.admin_users DROP CONSTRAINT IF EXISTS admin_users_email_key;
    DROP INDEX IF EXISTS public.admin_users_email_key;

    -- 2. Cleanup duplicates by email before adding constraint
    DELETE FROM public.admin_users a
    WHERE a.ctid <> (
        SELECT min(b.ctid)
        FROM public.admin_users b
        WHERE lower(trim(b.email)) = lower(trim(a.email))
    );

    -- 3. Add the unique constraint
    ALTER TABLE public.admin_users ADD CONSTRAINT admin_users_email_key UNIQUE (email);
EXCEPTION WHEN OTHERS THEN
    -- If adding constraint fails (e.g. still has duplicates), we log it but don't stop the migration
    RAISE NOTICE 'Could not add unique constraint: %', SQLERRM;
END $$;

-- 3. UTILITY FUNCTIONS
CREATE OR REPLACE FUNCTION public.has_role(_user_id uuid, _role text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.user_roles
    WHERE user_id = _user_id AND lower(role::text) = lower(_role)
  );
$$;

-- 4. CLEAN UP ACCIDENTAL ADMINS
DO $$
DECLARE
    _emails text[] := ARRAY['rhallhanin@gmail.com', 'gharamrahal6@gmil.com', 'gharamrahal6@gmail.com', 'rhaalhanin@gmail.com', 'almwshlyjyhan@gmail.com'];
BEGIN
    UPDATE public.user_roles SET role = 'user'::public.app_role WHERE user_id IN (SELECT id FROM auth.users WHERE trim(lower(email)) = ANY(_emails));
    UPDATE public.admin_users SET role = 'User' WHERE trim(lower(email)) = ANY(_emails);
END $$;

-- 5. HYPER-RESILIENT TRIGGER FUNCTION (v10 Final)
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
    _user_full_name text;
    _target_role text := 'user';
    _target_role_label text := 'User';
    _clean_email text;
BEGIN
    BEGIN
        _clean_email := trim(lower(NEW.email));
        _user_full_name := COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.email);

        -- Role Whitelisting
        IF _clean_email IN ('akatsukigh510@gmail.com', 'jehanmoshle@gmail.com') THEN
            _target_role := 'admin';
            _target_role_label := 'Admin';
        END IF;

        -- ADOPTION LOGIC (Delete placeholders with different IDs)
        BEGIN
            DELETE FROM public.user_roles WHERE user_id IN (SELECT id FROM public.admin_users WHERE trim(lower(email)) = _clean_email AND id <> NEW.id);
        EXCEPTION WHEN OTHERS THEN NULL; END;

        BEGIN
            DELETE FROM public.admin_users WHERE trim(lower(email)) = _clean_email AND id <> NEW.id;
        EXCEPTION WHEN OTHERS THEN NULL; END;

        -- SYNC user_roles
        BEGIN
            INSERT INTO public.user_roles (user_id, role)
            VALUES (NEW.id, _target_role::public.app_role)
            ON CONFLICT (user_id) DO UPDATE SET role = EXCLUDED.role;
        EXCEPTION WHEN OTHERS THEN NULL; END;

        -- SYNC admin_users
        BEGIN
            INSERT INTO public.admin_users (id, email, name, role, joined_at)
            VALUES (NEW.id, NEW.email, _user_full_name, _target_role_label, NOW())
            ON CONFLICT (email) DO UPDATE SET id = EXCLUDED.id, name = EXCLUDED.name, role = EXCLUDED.role;
        EXCEPTION WHEN OTHERS THEN
            BEGIN
                INSERT INTO public.admin_users (id, email, name, role, joined_at)
                VALUES (NEW.id, NEW.email, _user_full_name, _target_role_label, NOW())
                ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email, name = EXCLUDED.name, role = EXCLUDED.role;
            EXCEPTION WHEN OTHERS THEN NULL; END;
        END;

    EXCEPTION WHEN OTHERS THEN
        RETURN NEW;
    END;
    RETURN NEW;
END;
$$;

-- 6. RE-ATTACH TRIGGER
CREATE TRIGGER on_auth_user_created AFTER INSERT ON auth.users FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- 7. REFINED INVITATION FULFILLMENT
CREATE OR REPLACE FUNCTION public.use_invitation_token(token_param text, user_id_param uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  inv RECORD;
  user_email text;
BEGIN
  SELECT email INTO user_email FROM auth.users WHERE id = user_id_param;
  SELECT * INTO inv FROM public.invitation_links WHERE token = token_param AND is_active = true AND (expires_at IS NULL OR expires_at > now());
  IF inv IS NULL THEN RETURN false; END IF;
  IF inv.email IS NOT NULL AND trim(lower(inv.email)) <> trim(lower(user_email)) THEN RETURN false; END IF;
  INSERT INTO public.invitation_usages (invitation_id, user_id) VALUES (inv.id, user_id_param) ON CONFLICT DO NOTHING;
  UPDATE public.invitation_links SET uses_count = uses_count + 1 WHERE id = inv.id;
  UPDATE public.user_roles SET role = 'user'::public.app_role WHERE user_id = user_id_param;
  UPDATE public.admin_users SET role = 'User' WHERE id = user_id_param;
  RETURN true;
END;
$$;

-- 8. STANDARDIZATION & BACKFILL
UPDATE public.admin_users SET role = 'Admin' WHERE lower(role) = 'admin';
UPDATE public.admin_users SET role = 'User' WHERE lower(role) = 'user' OR role IS NULL;

INSERT INTO public.user_roles (user_id, role)
SELECT id, 'user'::public.app_role FROM auth.users
ON CONFLICT (user_id) DO NOTHING;

INSERT INTO public.admin_users (id, email, name, role, joined_at)
SELECT u.id, u.email, COALESCE(u.raw_user_meta_data->>'full_name', u.email), 'User', u.created_at
FROM auth.users u
WHERE NOT EXISTS (SELECT 1 FROM public.admin_users a WHERE a.id = u.id OR lower(trim(a.email)) = lower(trim(u.email)))
ON CONFLICT (email) DO NOTHING;

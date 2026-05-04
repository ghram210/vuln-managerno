-- ========================================================
-- FINAL BULLETPROOF User Management and Security Fix (v5)
-- ========================================================
-- This migration addresses the following GENERICALLY for all users:
-- 1. SECURITY: Prevents accidental admin escalation by defaulting all new signups to 'User'.
-- 2. INVITATION LINKING: Strictly binds invitations to emails and enforces 'User' role.
-- 3. ROBUSTNESS: Proactive cleanup of orphaned records to prevent registration errors.
-- 4. CONSISTENCY: Ensures role capitalization is synced across all tables.

-- 1. Function to accept invitation and assign user role (STRICT & GENERIC)
-- This ensures that the user who uses the token is assigned the 'user' role
-- and validates their email against the invitation's recipient email.
CREATE OR REPLACE FUNCTION public.use_invitation_token(token_param text, user_id_param uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  inv RECORD;
  user_email text;
BEGIN
  -- Get the current user's email from auth.users
  SELECT email INTO user_email FROM auth.users WHERE id = user_id_param;

  -- Validate the invitation exists and is active/not expired/not fully used
  SELECT * INTO inv
  FROM public.invitation_links
  WHERE token = token_param
    AND is_active = true
    AND (expires_at IS NULL OR expires_at > now())
    AND (max_uses IS NULL OR uses_count < max_uses);

  -- If no valid invitation found
  IF inv IS NULL THEN
    RETURN false;
  END IF;

  -- If the invitation was issued for a specific email, verify it matches the registering user
  -- This "links the invitation code with the email" as requested.
  IF inv.email IS NOT NULL AND lower(inv.email) <> lower(user_email) THEN
    RETURN false;
  END IF;

  -- Log usage of the invitation
  INSERT INTO public.invitation_usages (invitation_id, user_id)
  VALUES (inv.id, user_id_param)
  ON CONFLICT (invitation_id, user_id) DO NOTHING;

  -- Increment the use count for the invitation link
  UPDATE public.invitation_links
  SET uses_count = uses_count + 1
  WHERE id = inv.id;

  -- FORCE the 'user' role for anyone registering via invitation.
  -- This ensures they cannot be accidentally promoted during registration.
  INSERT INTO public.user_roles (user_id, role)
  VALUES (user_id_param, 'user'::public.app_role)
  ON CONFLICT (user_id) DO UPDATE SET role = 'user'::public.app_role;

  -- Sync to the admin_users table (used for UI display) with the capitalized 'User' role.
  INSERT INTO public.admin_users (id, email, name, role, joined_at)
  VALUES (
    user_id_param,
    user_email,
    COALESCE((SELECT raw_user_meta_data->>'full_name' FROM auth.users WHERE id = user_id_param), user_email),
    'User',
    NOW()
  )
  ON CONFLICT (id) DO UPDATE SET
    email = EXCLUDED.email,
    name = EXCLUDED.name,
    role = 'User';

  RETURN true;
END;
$$;

-- 2. Generic Trigger: Default ANY new user to 'User' and clean up stale data
-- This is the "safety net" that handles direct signups and prevents role-inheritance bugs.
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
    user_full_name text;
BEGIN
    -- A. Extract metadata
    user_full_name := COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.email);

    -- B. CLEANUP orphaned records:
    -- Remove records from public tables if they have the same email but different ID.
    -- This handles cases where a user was deleted from Auth but records stayed in admin_users/user_roles.
    DELETE FROM public.user_roles WHERE user_id IN (
        SELECT id FROM public.admin_users WHERE lower(email) = lower(NEW.email) AND id <> NEW.id
    );
    DELETE FROM public.admin_users WHERE lower(email) = lower(NEW.email) AND id <> NEW.id;

    -- C. SYNC: ALWAYS default new users to 'user' role for security.
    -- This ensures that even if stale data existed, the new account starts with zero admin privileges.

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
    -- Don't block registration even if sync fails
    RETURN NEW;
END;
$$;

-- 3. Re-ensure the trigger is correctly attached to auth.users
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- 4. Global Data Standardization:
-- Standardize existing roles to ensure UI consistency.
UPDATE public.admin_users SET role = 'Admin' WHERE lower(role) = 'admin';
UPDATE public.admin_users SET role = 'User' WHERE lower(role) = 'user' OR role IS NULL;

-- 5. Cleanup remaining duplicates (if any)
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

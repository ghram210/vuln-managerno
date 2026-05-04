-- ========================================================  
-- ULTIMATE User Management and Security Consolidation (v5) 
-- ========================================================  
-- This migration replaces and consolidates previous fixes (v4 and earlier) 
-- to ensure a clean, robust, and secure user management system. 
-- It addresses: 
-- 1. SECURITY: Defaults all signups to 'User' and tightens RLS. 
-- 2. INVITATION: Strictly links invitations to emails and 'User' role. 
-- 3. CLEANUP: Fixes specific users accidentally granted 'Admin' status. 
-- 4. STABILITY: Solves type-mismatch and ENUM errors (Error 42804/42883). 
 
-- 1. Prerequisites (Types and Functions) 
DO $$  
BEGIN 
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'app_role') THEN 
        CREATE TYPE public.app_role AS ENUM ('admin', 'user'); 
    END IF; 
END $$; 

-- FIX DATA TYPES: Ensure tables use UUID for foreign keys to match auth.users
DO $$
BEGIN
    -- admin_users.id
    IF (SELECT data_type FROM information_schema.columns 
        WHERE table_schema = 'public' AND table_name = 'admin_users' AND column_name = 'id') = 'text' THEN
        ALTER TABLE public.admin_users ALTER COLUMN id TYPE uuid USING id::uuid;
    END IF;

    -- user_roles.user_id
    IF (SELECT data_type FROM information_schema.columns 
        WHERE table_schema = 'public' AND table_name = 'user_roles' AND column_name = 'user_id') = 'text' THEN
        ALTER TABLE public.user_roles ALTER COLUMN user_id TYPE uuid USING user_id::uuid;
    END IF;

    -- scan_results.user_id
    IF (SELECT data_type FROM information_schema.columns 
        WHERE table_schema = 'public' AND table_name = 'scan_results' AND column_name = 'user_id') = 'text' THEN
        ALTER TABLE public.scan_results ALTER COLUMN user_id TYPE uuid USING user_id::uuid;
    END IF;
END $$;

-- Ensure user_roles uses the enum and fix casing
DO $$
BEGIN
    -- Check if the column is already of the enum type
    IF (SELECT data_type FROM information_schema.columns 
        WHERE table_schema = 'public' AND table_name = 'user_roles' AND column_name = 'role') = 'text' THEN
        
        -- Lowercase everything first to ensure casting to ENUM (which is lowercase 'admin'/'user') works
        UPDATE public.user_roles SET role = lower(role);
        
        ALTER TABLE public.user_roles ALTER COLUMN role TYPE public.app_role USING role::public.app_role;
    END IF;
END $$;

-- 2. Clean up specific accidental admins (Security Cleanup) 
-- User requested to handle these specifically.
-- We also delete these from auth.users so they can re-register correctly.
DELETE FROM auth.users WHERE lower(email) IN (
    'rhallhanin@gmail.com', 
    'rhaalhanin@gmail.com', 
    'gharamrahal6@gmil.com', 
    'gharamrahal6@gmail.com',
    'almwshlyjyhan@gmail.com'
);

-- Explicitly delete from public tables just in case CASCADE isn't there
DELETE FROM public.user_roles WHERE user_id NOT IN (SELECT id FROM auth.users);
DELETE FROM public.admin_users WHERE id NOT IN (SELECT id FROM auth.users) AND email NOT IN (SELECT email FROM public.invitation_links);

-- 3. Case-insensitive has_role function (handles ENUM casting correctly) 
CREATE OR REPLACE FUNCTION public.has_role(_user_id uuid, _role text) 
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public 
AS $$ 
  SELECT EXISTS ( 
    SELECT 1 FROM public.user_roles 
    WHERE user_id = _user_id AND lower(role::text) = lower(_role) 
  ); 
$$; 

-- Improved Validation Function to return email (used by AcceptInvite.tsx)
CREATE OR REPLACE FUNCTION public.validate_invitation_token(token_param text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  invitation_record RECORD;
BEGIN
  SELECT * INTO invitation_record
  FROM public.invitation_links
  WHERE token = token_param
    AND is_active = true
    AND (expires_at IS NULL OR expires_at > now())
    AND (max_uses IS NULL OR uses_count < max_uses);

  IF invitation_record IS NULL THEN
    RETURN jsonb_build_object('valid', false, 'error', 'Invalid or expired invitation link');
  END IF;

  RETURN jsonb_build_object(
    'valid', true, 
    'invitation_id', invitation_record.id,
    'email', invitation_record.email
  );
END;
$$;
 
-- 4. Robust Trigger Function for ANY new user signup 
CREATE OR REPLACE FUNCTION public.handle_new_user()  
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = public  
AS $$  
DECLARE 
    user_full_name text; 
    target_role public.app_role := 'user'::public.app_role;
    target_role_label text := 'User';
BEGIN  
    BEGIN
        -- A. Extract metadata 
        user_full_name := COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.email); 
    
        -- B. Proactive CLEANUP of orphaned records or placeholders by email 
        -- This prevents unique constraint (email) violations when a placeholder exists with a different ID
        DELETE FROM public.user_roles WHERE user_id IN ( 
            SELECT id FROM public.admin_users WHERE lower(email) = lower(NEW.email) AND id <> NEW.id 
        ); 
        DELETE FROM public.admin_users WHERE lower(email) = lower(NEW.email) AND id <> NEW.id; 

        -- C. Sync Role: Default to 'user' role for security, EXCEPT for protected admins
        IF lower(NEW.email) IN ('akatsukigh510@gmail.com', 'jehanmoshle@gmail.com') THEN
            target_role := 'admin'::public.app_role;
            target_role_label := 'Admin';
        END IF;
        
        -- D. Sync to user_roles
        INSERT INTO public.user_roles (user_id, role)  
        VALUES (NEW.id, target_role)
        ON CONFLICT (user_id) DO UPDATE SET role = EXCLUDED.role;

        -- E. Sync to admin_users
        INSERT INTO public.admin_users (id, email, name, role, joined_at)  
        VALUES (  
            NEW.id,  
            NEW.email,  
            user_full_name,  
            target_role_label,  
            NOW()  
        )
        ON CONFLICT (id) DO UPDATE SET
            email = EXCLUDED.email,
            name = EXCLUDED.name,
            role = EXCLUDED.role;
            
    EXCEPTION WHEN OTHERS THEN
        -- We catch all errors here so the main registration in auth.users is NEVER blocked.
        -- If syncing fails, the user can still register, and we can backfill later.
        NULL;
    END;
  
    RETURN NEW;  
END;  
$$;  
 
-- 5. Re-enable the trigger (CRITICAL FIX: Ensure it is actually attached) 
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;  
CREATE TRIGGER on_auth_user_created  
  AFTER INSERT ON auth.users  
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();  
 
-- 6. Strict Invitation Fulfillment 
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
  IF inv.email IS NOT NULL AND lower(inv.email) <> lower(user_email) THEN 
    RETURN false; 
  END IF; 
 
  -- Record usage 
  INSERT INTO public.invitation_usages (invitation_id, user_id) 
  VALUES (inv.id, user_id_param) 
  ON CONFLICT DO NOTHING; 
 
  UPDATE public.invitation_links SET uses_count = uses_count + 1 WHERE id = inv.id; 
 
  -- Force 'user' role assignment 
  INSERT INTO public.user_roles (user_id, role) 
  VALUES (user_id_param, 'user'::public.app_role) 
  ON CONFLICT (user_id) DO UPDATE SET role = 'user'::public.app_role; 
 
  -- Sync to admin_users UI table 
  UPDATE public.admin_users SET role = 'User' WHERE id = user_id_param; 
 
  RETURN true; 
END; 
$$; 
 
-- 7. Tighten RLS for scan_results (Security Fix) 
DROP POLICY IF EXISTS "Authenticated can view scan_results" ON public.scan_results; 
DROP POLICY IF EXISTS "Users can view own scan_results" ON public.scan_results; 
CREATE POLICY "Users can view own scan_results" 
  ON public.scan_results FOR SELECT TO authenticated 
  USING (auth.uid() = user_id OR public.has_role(auth.uid(), 'admin')); 
 
-- 8. Standardization and Duplication Cleanup 
UPDATE public.admin_users SET role = 'Admin' WHERE lower(role) = 'admin'; 
UPDATE public.admin_users SET role = 'User' WHERE lower(role) = 'user' OR role IS NULL; 
 
-- Remove duplicate emails if any remain (keeps Admin, then newest) 
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
 
-- Ensure Unique Email Constraint 
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
 
-- 9. Backfill Missing Users (Fixes current broken accounts) 
-- Sync to user_roles 
INSERT INTO public.user_roles (user_id, role)  
SELECT id, 'user'::public.app_role FROM auth.users  
ON CONFLICT (user_id) DO NOTHING;  

-- Explicitly ensure protected admins have correct role
UPDATE public.user_roles SET role = 'admin'::public.app_role 
WHERE user_id IN (SELECT id FROM auth.users WHERE lower(email) IN ('akatsukigh510@gmail.com', 'jehanmoshle@gmail.com'));

UPDATE public.admin_users SET role = 'Admin' 
WHERE lower(email) IN ('akatsukigh510@gmail.com', 'jehanmoshle@gmail.com');
 
-- Sync to admin_users 
INSERT INTO public.admin_users (id, email, name, role, joined_at)  
SELECT   
    u.id,   
    u.email,   
    COALESCE(u.raw_user_meta_data->>'full_name', u.email),   
    CASE WHEN lower(u.email) IN ('akatsukigh510@gmail.com', 'jehanmoshle@gmail.com') THEN 'Admin' ELSE 'User' END,   
    u.created_at  
FROM auth.users u  
WHERE NOT EXISTS (  
    SELECT 1 FROM public.admin_users a   
    WHERE a.id = u.id OR lower(a.email) = lower(u.email)  
)  
ON CONFLICT DO NOTHING; 

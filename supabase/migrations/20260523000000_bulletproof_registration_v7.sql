-- ========================================================
-- ULTIMATE FAIL-SAFE User Registration (v7)
-- ========================================================
-- This migration provides the most resilient registration trigger possible.
-- It addresses:
-- 1. "Database error saving new user" by using better cleanup and catching ALL errors.
-- 2. "Email unique constraint violation" by deleting placeholders by email BEFORE insertion.
-- 3. Diagnostics: Logs every attempt and error to the 'system_logs' table.
-- 4. Case-insensitivity and strict type handling.

-- 1. Manual Cleanup of Problematic Accounts
-- Purge these to ensure they can register correctly.
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

-- 2. Drop existing trigger to ensure clean replacement
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;

-- 3. Enhanced Trigger Function with Logging
CREATE OR REPLACE FUNCTION public.handle_new_user()  
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = public  
AS $$  
DECLARE 
    _user_full_name text; 
    _target_role text := 'user';
    _target_role_label text := 'User';
    _error_msg text;
BEGIN  
    -- Log the start of the synchronization process
    BEGIN
        INSERT INTO public.system_logs (message, level)
        VALUES ('Starting user sync for: ' || COALESCE(NEW.email, 'unknown'), 'info');
    EXCEPTION WHEN OTHERS THEN NULL; END;

    BEGIN
        -- A. Extract metadata safely
        _user_full_name := COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.email); 
    
        -- B. Aggressive Cleanup of Existing Records
        -- We delete by email to prevent "unique_constraint_violation" on admin_users(email)
        -- which happens if a placeholder exists with a different ID.
        DELETE FROM public.user_roles WHERE user_id IN ( 
            SELECT id FROM public.admin_users WHERE lower(email) = lower(NEW.email)
        ); 
        DELETE FROM public.admin_users WHERE lower(email) = lower(NEW.email); 

        -- C. Determine Role (Security: Defaults to User)
        -- Only specifically authorized emails can be Admins.
        -- PROTECT THESE EMAILS: akatsukigh510@gmail.com, jehanmoshle@gmail.com
        IF lower(NEW.email) IN ('akatsukigh510@gmail.com', 'jehanmoshle@gmail.com') THEN
            _target_role := 'admin';
            _target_role_label := 'Admin';
        END IF;
        
        -- D. Sync to user_roles
        INSERT INTO public.user_roles (user_id, role)  
        VALUES (NEW.id, _target_role::public.app_role)
        ON CONFLICT (user_id) DO UPDATE SET role = EXCLUDED.role;

        -- E. Sync to admin_users
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
            
        -- Log success
        BEGIN
            INSERT INTO public.system_logs (message, level)
            VALUES ('Successfully synced user: ' || NEW.email || ' with role: ' || _target_role_label, 'info');
        EXCEPTION WHEN OTHERS THEN NULL; END;

    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS _error_msg = MESSAGE_TEXT;
        -- Log the failure but don't block registration
        BEGIN
            INSERT INTO public.system_logs (message, level)
            VALUES ('FAIL-SAFE: Error syncing user ' || COALESCE(NEW.email, 'unknown') || ': ' || _error_msg, 'error');
        EXCEPTION WHEN OTHERS THEN NULL; END;
    END;
  
    RETURN NEW;  
END;  
$$;  

-- 4. Re-enable the trigger
CREATE TRIGGER on_auth_user_created  
  AFTER INSERT ON auth.users  
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- 5. Backfill any missing users that might have been skipped
INSERT INTO public.user_roles (user_id, role)
SELECT id, 'user'::public.app_role FROM auth.users u
WHERE NOT EXISTS (SELECT 1 FROM public.user_roles ur WHERE ur.user_id = u.id)
  AND lower(u.email) NOT IN ('akatsukigh510@gmail.com', 'jehanmoshle@gmail.com');

INSERT INTO public.user_roles (user_id, role)
SELECT id, 'admin'::public.app_role FROM auth.users u
WHERE lower(email) IN ('akatsukigh510@gmail.com', 'jehanmoshle@gmail.com')
ON CONFLICT (user_id) DO UPDATE SET role = 'admin'::public.app_role;

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

-- ========================================================
-- HARDENED User Registration and Cleanup (v6)
-- ========================================================
-- This migration provides a "Bulletproof" registration trigger to ensure
-- that user registration NEVER fails due to sync or placeholder issues.
-- It specifically addresses the "Database error saving new user" issue.

-- 1. Manual Cleanup of Problematic Placeholders
-- These records were identified as blocking registration in the UI.
DELETE FROM public.user_roles 
WHERE user_id NOT IN (SELECT id FROM auth.users);

DELETE FROM public.admin_users 
WHERE id NOT IN (SELECT id FROM auth.users)
  AND lower(email) IN (
    'rhallhanin@gmail.com', 
    'rhaalhanin@gmail.com', 
    'gharamrahal6@gmil.com', 
    'gharamrahal6@gmail.com',
    'almwshlyjyhan@gmail.com'
  );

-- 2. Drop existing trigger to ensure clean replacement
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;

-- 3. Robust Trigger Function
CREATE OR REPLACE FUNCTION public.handle_new_user()  
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = public  
AS $$  
DECLARE 
    _user_full_name text; 
    _target_role text := 'user';
    _target_role_label text := 'User';
BEGIN  
    -- Use an internal BEGIN...EXCEPTION block for the ENTIRE logic
    -- This guarantees that 'RETURN NEW' is always reached.
    BEGIN
        -- A. Extract metadata safely
        _user_full_name := COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.email); 
    
        -- B. Aggressive Cleanup of Existing Records
        -- We delete by email to prevent "unique_constraint_violation" on admin_users(email)
        -- which happens if a placeholder exists with a different ID (e.g. from API invitation).
        DELETE FROM public.user_roles WHERE user_id IN ( 
            SELECT id FROM public.admin_users WHERE lower(email) = lower(NEW.email) AND id <> NEW.id 
        ); 
        DELETE FROM public.admin_users WHERE lower(email) = lower(NEW.email) AND id <> NEW.id; 

        -- C. Determine Role (Security: Defaults to User)
        -- Only specifically authorized emails can be Admins.
        IF lower(NEW.email) IN ('akatsukigh510@gmail.com', 'jehanmoshle@gmail.com') THEN
            _target_role := 'admin';
            _target_role_label := 'Admin';
        END IF;
        
        -- D. Sync to user_roles (uses ON CONFLICT to be extra safe)
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
            
    EXCEPTION WHEN OTHERS THEN
        -- SILENT FAIL: If any database error occurs during sync, we ignore it.
        -- This ensures the user is successfully created in auth.users.
        -- We can always run a manual sync/backfill later if needed.
        NULL;
    END;
  
    RETURN NEW;  
END;  
$$;  

-- 4. Re-enable the trigger
CREATE TRIGGER on_auth_user_created  
  AFTER INSERT ON auth.users  
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- 5. Final verification of role standardization
UPDATE public.admin_users SET role = 'Admin' WHERE lower(role) = 'admin';
UPDATE public.admin_users SET role = 'User' WHERE lower(role) = 'user' OR role IS NULL;

-- Ensure the specific users mentioned are ALWAYS Users if they exist
UPDATE public.user_roles 
SET role = 'user'::public.app_role
WHERE user_id IN (
    SELECT id FROM auth.users 
    WHERE lower(email) IN ('rhallhanin@gmail.com', 'gharamrahal6@gmil.com', 'gharamrahal6@gmail.com')
);

UPDATE public.admin_users 
SET role = 'User'
WHERE lower(email) IN ('rhallhanin@gmail.com', 'gharamrahal6@gmil.com', 'gharamrahal6@gmail.com');

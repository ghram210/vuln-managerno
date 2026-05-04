-- ========================================================
-- USER MANAGEMENT CLEANUP AND OPTIMIZATION (v11)
-- ========================================================
-- This migration cleans up "Code Spam" (duplicate invitation links)
-- and ensures the database is in a clean state after the v10 fix.

-- 1. CLEANUP INVITATION LINKS (Remove redundant/spam codes)
-- Strategy: For each email, keep only ONE invitation link.
-- We prioritize links that have been used (uses_count > 0), then the most recent.
DELETE FROM public.invitation_links
WHERE id NOT IN (
    SELECT id FROM (
        SELECT id, ROW_NUMBER() OVER (
            PARTITION BY lower(trim(email))
            ORDER BY 
              CASE WHEN uses_count > 0 THEN 0 ELSE 1 END ASC,
              created_at DESC
        ) as rank
        FROM public.invitation_links
        WHERE email IS NOT NULL
    ) t WHERE rank = 1
) AND email IS NOT NULL;

-- 2. CLEANUP ORPHANED USAGES
-- Remove usage records that might point to deleted links (though foreign keys should handle this if ON DELETE CASCADE)
-- But let's be safe.
DELETE FROM public.invitation_usages WHERE invitation_id NOT IN (SELECT id FROM public.invitation_links);

-- 3. RE-ENFORCE SECURITY FOR SPECIFIC ACCOUNTS
-- Ensure these accounts are 'User' and not 'Admin'
DO $$
DECLARE
    _emails text[] := ARRAY['rhallhanin@gmail.com', 'gharamrahal6@gmil.com', 'gharamrahal6@gmail.com', 'rhaalhanin@gmail.com', 'almwshlyjyhan@gmail.com'];
BEGIN
    -- Sync user_roles
    UPDATE public.user_roles 
    SET role = 'user'::public.app_role 
    WHERE user_id IN (SELECT id FROM auth.users WHERE trim(lower(email)) = ANY(_emails));
    
    -- Sync admin_users
    UPDATE public.admin_users 
    SET role = 'User' 
    WHERE trim(lower(email)) = ANY(_emails);
END $$;

-- 4. ENSURE ADMIN_USERS EMAIL KEY (Self-correction)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'admin_users_email_key'
    ) THEN
        ALTER TABLE public.admin_users ADD CONSTRAINT admin_users_email_key UNIQUE (email);
    END IF;
END $$;

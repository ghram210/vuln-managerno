-- ========================================================
-- ULTIMATE DUPLICATION CLEANUP (v12)
-- ========================================================
-- This migration ensures that NO email has more than one row in the invitation_links table.
-- It also cleans up any remaining orphans or duplicates in admin_users.

-- 1. CLEANUP ALL INVITATION LINKS DUPLICATES (For any email)
-- This keeps only the most relevant link for EVERY email in the system.
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

-- 2. CLEANUP ADMIN_USERS DUPLICATES (By email)
-- This ensures that every email corresponds to exactly one row in the UI table.
DELETE FROM public.admin_users
WHERE id NOT IN (
    SELECT id FROM (
        SELECT id, ROW_NUMBER() OVER (
            PARTITION BY lower(trim(email))
            ORDER BY 
              CASE WHEN role = 'Admin' THEN 0 ELSE 1 END ASC,
              joined_at DESC
        ) as rank
        FROM public.admin_users
    ) t WHERE rank = 1
);

-- 3. ENSURE UNIQUE CONSTRAINT (Safety Lock)
-- This prevents the database from ever allowing a duplicate email in the UI table again.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'admin_users_email_key') THEN
        ALTER TABLE public.admin_users ADD CONSTRAINT admin_users_email_key UNIQUE (email);
    END IF;
END $$;

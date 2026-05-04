-- =============================================
-- Fix: Ensure invitation_links has email column
-- =============================================

DO $$ 
BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='invitation_links' AND column_name='email') THEN
    ALTER TABLE public.invitation_links ADD COLUMN email text;
  END IF;
END $$;

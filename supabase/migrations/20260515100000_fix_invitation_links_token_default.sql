-- =============================================
-- Fix: Ensure invitation_links uses supported 'hex' encoding for tokens
-- =============================================

-- Explicitly set the default to 'hex' encoding to avoid 'base64url' errors
ALTER TABLE public.invitation_links 
ALTER COLUMN token SET DEFAULT encode(gen_random_bytes(32), 'hex');

-- Ensure all required columns exist
DO $$ 
BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='invitation_links' AND column_name='email') THEN
    ALTER TABLE public.invitation_links ADD COLUMN email text;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='invitation_links' AND column_name='is_active') THEN
    ALTER TABLE public.invitation_links ADD COLUMN is_active boolean DEFAULT true;
  END IF;
END $$;

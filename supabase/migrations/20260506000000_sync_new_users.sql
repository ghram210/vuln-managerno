-- =============================================
-- Final Fix: Sync Invitations and User Roles (Corrected Types)
-- =============================================

-- 1. Add missing column if not exists
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='invitation_links' AND column_name='is_active') THEN
    ALTER TABLE public.invitation_links ADD COLUMN is_active boolean DEFAULT true;
  END IF;
END $$;

-- 2. Update/Create the handle_new_user function
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  -- A. Ensure user has 'user' role in user_roles
  INSERT INTO public.user_roles (user_id, role)
  VALUES (NEW.id, 'user')
  ON CONFLICT (user_id) DO NOTHING;

  -- B. Sync user to admin_users
  INSERT INTO public.admin_users (id, email, name, role, joined_at)
  VALUES (
    NEW.id, -- Use UUID directly
    NEW.email,
    COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.email),
    'User',
    NOW()
  )
  ON CONFLICT (id) DO UPDATE SET
    email = EXCLUDED.email,
    name = EXCLUDED.name;

  RETURN NEW;
END;
$$;

-- 3. Ensure the trigger is active on auth.users
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- 4. Backfill existing users
INSERT INTO public.user_roles (user_id, role)
SELECT id, 'user' FROM auth.users
ON CONFLICT (user_id) DO NOTHING;

INSERT INTO public.admin_users (id, email, name, role, joined_at)
SELECT
  id, -- Use UUID directly
  email,
  COALESCE(raw_user_meta_data->>'full_name', email),
  'User',
  created_at
FROM auth.users
WHERE id NOT IN (SELECT id FROM public.admin_users WHERE role = 'Admin')
ON CONFLICT (id) DO NOTHING;

-- Supabase schema for NexaBot / Quantara
-- Create core tables used by the application. Paste into Supabase SQL editor.

-- users are managed by Supabase auth; these tables reference auth.users via user_id (uuid/text depending on setup)

CREATE TABLE IF NOT EXISTS profiles (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id text NOT NULL,
  full_name text,
  business_name text,
  website_url text,
  created_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS user_settings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id text NOT NULL,
  theme_primary_color text,
  theme_secondary_color text,
  website_url text,
  created_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS chatbot_configs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  bot_id text,
  user_id text,
  channel text,
  domain text,
  settings jsonb DEFAULT '{}'::jsonb,
  created_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS training_documents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  bot_id text,
  user_id text,
  source text,
  content text,
  embedding double precision[],
  created_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS domain_verifications (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  domain text NOT NULL,
  token_hash text NOT NULL,
  expires_at timestamptz,
  used_at timestamptz,
  created_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS domains (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  domain text NOT NULL UNIQUE,
  verified boolean DEFAULT false,
  verified_at timestamptz,
  created_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS email_verifications (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id text NOT NULL,
  email text NOT NULL,
  token_hash text NOT NULL,
  expires_at timestamptz,
  used_at timestamptz,
  created_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS security_logs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id text,
  action text,
  details jsonb,
  created_at timestamptz DEFAULT now()
);

-- Helper RPC: log_security_event
CREATE OR REPLACE FUNCTION public.log_security_event(p_user_id text, p_action text, p_ip_address text, p_user_agent text, p_success boolean, p_details jsonb DEFAULT '{}'::jsonb)
RETURNS void LANGUAGE sql AS $$
INSERT INTO security_logs(user_id, action, details) VALUES (p_user_id, p_action, jsonb_build_object('ip', p_ip_address, 'user_agent', p_user_agent, 'success', p_success, 'details', p_details));
$$;

-- RPC to verify email token hash and mark used
CREATE OR REPLACE FUNCTION public.verify_email_hash(p_hash text)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  UPDATE email_verifications
  SET used_at = now()
  WHERE token_hash = p_hash AND used_at IS NULL AND expires_at > now();
END;
$$;

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_training_bot_id ON training_documents(bot_id);
CREATE INDEX IF NOT EXISTS idx_profiles_user_id ON profiles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_settings_user_id ON user_settings(user_id);
CREATE INDEX IF NOT EXISTS idx_chatbot_configs_user_id ON chatbot_configs(user_id);
CREATE INDEX IF NOT EXISTS idx_email_verifications_user_id ON email_verifications(user_id);
CREATE INDEX IF NOT EXISTS idx_domain_verifications_domain ON domain_verifications(domain);

-- Note: Adjust user_id column type to uuid if your Supabase auth uses uuid. Replace text with uuid where appropriate.

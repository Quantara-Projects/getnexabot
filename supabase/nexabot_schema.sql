-- NexaBot Supabase schema
-- Paste this into a new Supabase project's SQL editor.

create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null unique references auth.users(id) on delete cascade,
  full_name text,
  business_name text,
  website_url text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.user_settings (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null unique references auth.users(id) on delete cascade,
  theme_primary_color text default '#22d3c8',
  theme_secondary_color text,
  website_url text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.chatbot_configs (
  id uuid primary key default gen_random_uuid(),
  bot_id text not null unique,
  user_id uuid not null references auth.users(id) on delete cascade,
  public_api_key text not null unique,
  channel text not null default 'website',
  domain text not null,
  runtime_mode text not null default 'live' check (runtime_mode in ('live', 'localhost', 'both')),
  status text not null default 'draft' check (status in ('draft', 'active', 'paused')),
  settings jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.training_documents (
  id uuid primary key default gen_random_uuid(),
  bot_id text not null references public.chatbot_configs(bot_id) on delete cascade,
  user_id uuid references auth.users(id) on delete cascade,
  source text not null,
  content text not null,
  embedding double precision[],
  created_at timestamptz not null default now()
);

create table if not exists public.domains (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete cascade,
  domain text not null unique,
  verified boolean not null default false,
  verified_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists public.domain_verifications (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete cascade,
  domain text not null,
  token_hash text not null,
  expires_at timestamptz not null,
  used_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists public.subscriptions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null unique references auth.users(id) on delete cascade,
  plan_name text not null default 'Beta Access Plan',
  status text not null default 'active',
  trial_started_at timestamptz not null default now(),
  trial_ends_at timestamptz not null default (now() + interval '3 months'),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.email_verifications (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  email text not null,
  token_hash text not null,
  expires_at timestamptz not null,
  used_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists public.security_logs (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete set null,
  action text not null,
  details jsonb default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists idx_chatbot_configs_user_id on public.chatbot_configs(user_id);
create index if not exists idx_chatbot_configs_public_api_key on public.chatbot_configs(public_api_key);
create index if not exists idx_training_documents_bot_id on public.training_documents(bot_id);
create index if not exists idx_domain_verifications_domain on public.domain_verifications(domain);
create index if not exists idx_security_logs_user_id on public.security_logs(user_id);

alter table public.profiles enable row level security;
alter table public.user_settings enable row level security;
alter table public.chatbot_configs enable row level security;
alter table public.training_documents enable row level security;
alter table public.domains enable row level security;
alter table public.domain_verifications enable row level security;
alter table public.subscriptions enable row level security;
alter table public.email_verifications enable row level security;
alter table public.security_logs enable row level security;

create policy "profiles owner access" on public.profiles for all using (auth.uid() = user_id) with check (auth.uid() = user_id);
create policy "settings owner access" on public.user_settings for all using (auth.uid() = user_id) with check (auth.uid() = user_id);
create policy "bots owner access" on public.chatbot_configs for all using (auth.uid() = user_id) with check (auth.uid() = user_id);
create policy "training owner access" on public.training_documents for all using (auth.uid() = user_id) with check (auth.uid() = user_id);
create policy "domains owner access" on public.domains for all using (auth.uid() = user_id) with check (auth.uid() = user_id);
create policy "domain verifications owner access" on public.domain_verifications for all using (auth.uid() = user_id) with check (auth.uid() = user_id);
create policy "subscriptions owner read" on public.subscriptions for select using (auth.uid() = user_id);
create policy "email verifications owner access" on public.email_verifications for all using (auth.uid() = user_id) with check (auth.uid() = user_id);
create policy "security logs owner read" on public.security_logs for select using (auth.uid() = user_id);
create policy "security logs owner insert" on public.security_logs for insert with check (auth.uid() = user_id or user_id is null);

create or replace function public.log_security_event(
  p_user_id uuid,
  p_action text,
  p_ip_address text,
  p_user_agent text,
  p_success boolean,
  p_details jsonb default '{}'::jsonb
)
returns void
language sql
security definer
as $$
  insert into public.security_logs(user_id, action, details)
  values (
    p_user_id,
    p_action,
    jsonb_build_object(
      'ip', p_ip_address,
      'user_agent', p_user_agent,
      'success', p_success,
      'details', coalesce(p_details, '{}'::jsonb)
    )
  );
$$;

create or replace function public.verify_email_hash(p_hash text)
returns void
language plpgsql
security definer
as $$
begin
  update public.email_verifications
  set used_at = now()
  where token_hash = p_hash
    and used_at is null
    and expires_at > now();
end;
$$;

create or replace function public.create_beta_subscription()
returns trigger
language plpgsql
security definer
as $$
begin
  insert into public.subscriptions(user_id)
  values (new.id)
  on conflict (user_id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created_beta_subscription on auth.users;
create trigger on_auth_user_created_beta_subscription
after insert on auth.users
for each row execute function public.create_beta_subscription();


-- OSINT MCP Hub initial Supabase schema.
-- Assumes Supabase Auth owns auth.users. Do not create auth users manually.

create extension if not exists pgcrypto;
create extension if not exists citext;
create schema if not exists vault;
create extension if not exists supabase_vault with schema vault;

create schema if not exists private;

do $$
begin
  create type public.plan_tier as enum ('community', 'team', 'enterprise');
exception
  when duplicate_object then null;
end $$;

do $$
begin
  create type public.org_role as enum ('owner', 'admin', 'analyst', 'viewer');
exception
  when duplicate_object then null;
end $$;

do $$
begin
  create type public.member_status as enum ('active', 'invited', 'suspended');
exception
  when duplicate_object then null;
end $$;

do $$
begin
  create type public.ioc_type as enum (
    'ipv4',
    'ipv6',
    'domain',
    'url',
    'md5',
    'sha1',
    'sha256',
    'email',
    'phone',
    'unknown'
  );
exception
  when duplicate_object then null;
end $$;

do $$
begin
  create type public.investigation_status as enum (
    'queued',
    'running',
    'completed',
    'failed'
  );
exception
  when duplicate_object then null;
end $$;

do $$
begin
  create type public.api_key_provider as enum (
    'virustotal',
    'shodan',
    'abuseipdb',
    'firecrawl',
    'otx',
    'urlscan',
    'custom'
  );
exception
  when duplicate_object then null;
end $$;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email citext,
  display_name text,
  default_org_id uuid,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.organizations (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(name) between 2 and 120),
  slug citext not null unique check (slug ~ '^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$'),
  plan public.plan_tier not null default 'community',
  daily_free_quota integer not null default 10 check (daily_free_quota >= 0),
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.profiles
  add constraint profiles_default_org_id_fkey
  foreign key (default_org_id) references public.organizations(id)
  on delete set null;

create table if not exists public.organization_members (
  org_id uuid not null references public.organizations(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role public.org_role not null default 'analyst',
  status public.member_status not null default 'active',
  invited_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (org_id, user_id)
);

create table if not exists public.mcp_provider_catalog (
  provider public.api_key_provider primary key,
  mcp_server_name text not null,
  display_name text not null,
  requires_api_key boolean not null default true,
  enabled boolean not null default true,
  created_at timestamptz not null default now()
);

insert into public.mcp_provider_catalog (provider, mcp_server_name, display_name, requires_api_key)
values
  ('virustotal', 'mcp-virustotal', 'VirusTotal', true),
  ('shodan', 'mcp-shodan', 'Shodan', true),
  ('abuseipdb', 'mcp-abuseipdb', 'AbuseIPDB', true),
  ('firecrawl', 'mcp-firecrawl', 'Firecrawl', true),
  ('otx', 'mcp-otx', 'AlienVault OTX', true),
  ('urlscan', 'mcp-urlscan', 'urlscan.io', true)
on conflict (provider) do nothing;

create table if not exists public.user_api_keys (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  org_id uuid references public.organizations(id) on delete cascade,
  provider public.api_key_provider not null,
  label text not null default 'default',
  vault_secret_id uuid not null,
  key_last4 text check (key_last4 is null or char_length(key_last4) <= 8),
  enabled boolean not null default true,
  scopes text[] not null default '{}',
  metadata jsonb not null default '{}'::jsonb,
  last_used_at timestamptz,
  expires_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (user_id, org_id, provider, label)
);

create table if not exists public.daily_usage (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  usage_date date not null default current_date,
  free_queries_used integer not null default 0 check (free_queries_used >= 0),
  byok_queries_used integer not null default 0 check (byok_queries_used >= 0),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (org_id, user_id, usage_date)
);

create table if not exists public.investigations (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  raw_ioc text not null check (char_length(raw_ioc) between 1 and 4096),
  normalized_ioc text not null,
  ioc_type public.ioc_type not null default 'unknown',
  status public.investigation_status not null default 'queued',
  risk_score integer check (risk_score between 0 and 100),
  severity text check (severity is null or severity in ('unknown', 'low', 'medium', 'high', 'critical')),
  summary text,
  result_json jsonb not null default '{}'::jsonb,
  sources jsonb not null default '[]'::jsonb,
  mitre_attack_tags jsonb not null default '[]'::jsonb,
  nist_tags jsonb not null default '[]'::jsonb,
  iso_tags jsonb not null default '[]'::jsonb,
  used_byok boolean not null default false,
  mcp_servers_queried text[] not null default '{}',
  created_at timestamptz not null default now(),
  completed_at timestamptz
);

create table if not exists public.investigation_events (
  id uuid primary key default gen_random_uuid(),
  investigation_id uuid not null references public.investigations(id) on delete cascade,
  event_type text not null,
  payload jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists profiles_default_org_id_idx
  on public.profiles(default_org_id);

create index if not exists organization_members_user_id_idx
  on public.organization_members(user_id);

create index if not exists organization_members_org_role_idx
  on public.organization_members(org_id, role)
  where status = 'active';

create index if not exists user_api_keys_user_provider_idx
  on public.user_api_keys(user_id, provider)
  where enabled = true and revoked_at is null;

create index if not exists daily_usage_lookup_idx
  on public.daily_usage(org_id, user_id, usage_date);

create index if not exists investigations_org_created_idx
  on public.investigations(org_id, created_at desc);

create index if not exists investigations_user_created_idx
  on public.investigations(user_id, created_at desc);

create index if not exists investigations_ioc_lookup_idx
  on public.investigations(ioc_type, normalized_ioc);

create or replace function private.set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists profiles_set_updated_at on public.profiles;
create trigger profiles_set_updated_at
before update on public.profiles
for each row execute function private.set_updated_at();

drop trigger if exists organizations_set_updated_at on public.organizations;
create trigger organizations_set_updated_at
before update on public.organizations
for each row execute function private.set_updated_at();

drop trigger if exists organization_members_set_updated_at on public.organization_members;
create trigger organization_members_set_updated_at
before update on public.organization_members
for each row execute function private.set_updated_at();

drop trigger if exists user_api_keys_set_updated_at on public.user_api_keys;
create trigger user_api_keys_set_updated_at
before update on public.user_api_keys
for each row execute function private.set_updated_at();

drop trigger if exists daily_usage_set_updated_at on public.daily_usage;
create trigger daily_usage_set_updated_at
before update on public.daily_usage
for each row execute function private.set_updated_at();

create or replace function private.is_org_member(target_org_id uuid)
returns boolean
language sql
security definer
set search_path = public
stable
as $$
  select exists (
    select 1
    from public.organization_members om
    where om.org_id = target_org_id
      and om.user_id = (select auth.uid())
      and om.status = 'active'
  );
$$;

create or replace function private.has_org_role(target_org_id uuid, allowed_roles public.org_role[])
returns boolean
language sql
security definer
set search_path = public
stable
as $$
  select exists (
    select 1
    from public.organization_members om
    where om.org_id = target_org_id
      and om.user_id = (select auth.uid())
      and om.status = 'active'
      and om.role = any(allowed_roles)
  );
$$;

create or replace function private.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, email, display_name)
  values (
    new.id,
    new.email,
    coalesce(new.raw_user_meta_data ->> 'display_name', new.raw_user_meta_data ->> 'full_name')
  )
  on conflict (id) do update
    set email = excluded.email;

  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute function private.handle_new_user();

create or replace function public.create_organization(
  p_name text,
  p_slug text
)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  v_user_id uuid := (select auth.uid());
  v_org_id uuid;
begin
  if v_user_id is null then
    raise exception 'Authentication required';
  end if;

  insert into public.organizations (name, slug, created_by)
  values (trim(p_name), lower(trim(p_slug)), v_user_id)
  returning id into v_org_id;

  insert into public.organization_members (org_id, user_id, role, status)
  values (v_org_id, v_user_id, 'owner', 'active');

  update public.profiles
  set default_org_id = coalesce(default_org_id, v_org_id)
  where id = v_user_id;

  return v_org_id;
end;
$$;

create or replace function public.create_user_api_key(
  p_provider public.api_key_provider,
  p_plaintext_key text,
  p_label text default 'default',
  p_org_id uuid default null,
  p_scopes text[] default '{}'
)
returns uuid
language plpgsql
security definer
set search_path = public, vault
as $$
declare
  v_user_id uuid := (select auth.uid());
  v_secret_id uuid;
  v_api_key_id uuid;
  v_secret_name text;
begin
  if v_user_id is null then
    raise exception 'Authentication required';
  end if;

  if p_plaintext_key is null or char_length(p_plaintext_key) < 8 then
    raise exception 'API key is too short';
  end if;

  if p_org_id is not null and not private.is_org_member(p_org_id) then
    raise exception 'User is not a member of target organization';
  end if;

  v_secret_name := 'byok_' || v_user_id::text || '_' || gen_random_uuid()::text;

  select vault.create_secret(
    p_plaintext_key,
    v_secret_name,
    'BYOK key for ' || p_provider::text
  )
  into v_secret_id;

  insert into public.user_api_keys (
    user_id,
    org_id,
    provider,
    label,
    vault_secret_id,
    key_last4,
    scopes
  )
  values (
    v_user_id,
    p_org_id,
    p_provider,
    coalesce(nullif(trim(p_label), ''), 'default'),
    v_secret_id,
    right(p_plaintext_key, 4),
    coalesce(p_scopes, '{}')
  )
  returning id into v_api_key_id;

  return v_api_key_id;
end;
$$;

revoke all on schema vault from anon, authenticated;
revoke all on all tables in schema vault from anon, authenticated;
revoke all on all routines in schema vault from anon, authenticated;

grant usage on schema public to anon, authenticated;
grant execute on function public.create_organization(text, text) to authenticated;
grant execute on function public.create_user_api_key(
  public.api_key_provider,
  text,
  text,
  uuid,
  text[]
) to authenticated;

alter table public.profiles enable row level security;
alter table public.organizations enable row level security;
alter table public.organization_members enable row level security;
alter table public.mcp_provider_catalog enable row level security;
alter table public.user_api_keys enable row level security;
alter table public.daily_usage enable row level security;
alter table public.investigations enable row level security;
alter table public.investigation_events enable row level security;

drop policy if exists "profiles_select_own" on public.profiles;
create policy "profiles_select_own"
on public.profiles
for select
to authenticated
using ((select auth.uid()) = id);

drop policy if exists "profiles_update_own" on public.profiles;
create policy "profiles_update_own"
on public.profiles
for update
to authenticated
using ((select auth.uid()) = id)
with check ((select auth.uid()) = id);

drop policy if exists "organizations_select_member" on public.organizations;
create policy "organizations_select_member"
on public.organizations
for select
to authenticated
using ((select private.is_org_member(id)));

drop policy if exists "organizations_insert_creator" on public.organizations;
create policy "organizations_insert_creator"
on public.organizations
for insert
to authenticated
with check ((select auth.uid()) = created_by);

drop policy if exists "organizations_update_admin" on public.organizations;
create policy "organizations_update_admin"
on public.organizations
for update
to authenticated
using ((select private.has_org_role(id, array['owner', 'admin']::public.org_role[])))
with check ((select private.has_org_role(id, array['owner', 'admin']::public.org_role[])));

drop policy if exists "organization_members_select_same_org" on public.organization_members;
create policy "organization_members_select_same_org"
on public.organization_members
for select
to authenticated
using ((select private.is_org_member(org_id)));

drop policy if exists "organization_members_insert_admin" on public.organization_members;
create policy "organization_members_insert_admin"
on public.organization_members
for insert
to authenticated
with check ((select private.has_org_role(org_id, array['owner', 'admin']::public.org_role[])));

drop policy if exists "organization_members_update_admin" on public.organization_members;
create policy "organization_members_update_admin"
on public.organization_members
for update
to authenticated
using ((select private.has_org_role(org_id, array['owner', 'admin']::public.org_role[])))
with check ((select private.has_org_role(org_id, array['owner', 'admin']::public.org_role[])));

drop policy if exists "organization_members_delete_owner" on public.organization_members;
create policy "organization_members_delete_owner"
on public.organization_members
for delete
to authenticated
using ((select private.has_org_role(org_id, array['owner']::public.org_role[])));

drop policy if exists "mcp_provider_catalog_select_authenticated" on public.mcp_provider_catalog;
create policy "mcp_provider_catalog_select_authenticated"
on public.mcp_provider_catalog
for select
to authenticated
using (enabled = true);

drop policy if exists "user_api_keys_select_own" on public.user_api_keys;
create policy "user_api_keys_select_own"
on public.user_api_keys
for select
to authenticated
using ((select auth.uid()) = user_id);

drop policy if exists "user_api_keys_insert_own" on public.user_api_keys;
create policy "user_api_keys_insert_own"
on public.user_api_keys
for insert
to authenticated
with check (
  (select auth.uid()) = user_id
  and (org_id is null or (select private.is_org_member(org_id)))
);

drop policy if exists "user_api_keys_update_own" on public.user_api_keys;
create policy "user_api_keys_update_own"
on public.user_api_keys
for update
to authenticated
using ((select auth.uid()) = user_id)
with check ((select auth.uid()) = user_id);

drop policy if exists "user_api_keys_delete_own" on public.user_api_keys;
create policy "user_api_keys_delete_own"
on public.user_api_keys
for delete
to authenticated
using ((select auth.uid()) = user_id);

drop policy if exists "daily_usage_select_own" on public.daily_usage;
create policy "daily_usage_select_own"
on public.daily_usage
for select
to authenticated
using ((select auth.uid()) = user_id);

drop policy if exists "investigations_select_org_member" on public.investigations;
create policy "investigations_select_org_member"
on public.investigations
for select
to authenticated
using ((select private.is_org_member(org_id)));

drop policy if exists "investigations_insert_org_member" on public.investigations;
create policy "investigations_insert_org_member"
on public.investigations
for insert
to authenticated
with check (
  (select auth.uid()) = user_id
  and (select private.is_org_member(org_id))
);

drop policy if exists "investigations_update_admin_or_owner" on public.investigations;
create policy "investigations_update_admin_or_owner"
on public.investigations
for update
to authenticated
using (
  (select auth.uid()) = user_id
  or (select private.has_org_role(org_id, array['owner', 'admin']::public.org_role[]))
)
with check (
  (select auth.uid()) = user_id
  or (select private.has_org_role(org_id, array['owner', 'admin']::public.org_role[]))
);

drop policy if exists "investigation_events_select_org_member" on public.investigation_events;
create policy "investigation_events_select_org_member"
on public.investigation_events
for select
to authenticated
using (
  exists (
    select 1
    from public.investigations i
    where i.id = investigation_id
      and (select private.is_org_member(i.org_id))
  )
);

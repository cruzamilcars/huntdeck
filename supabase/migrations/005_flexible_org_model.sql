-- 005_flexible_org_model.sql
-- Removes hard FK constraints from daily_usage and investigations so the app can
-- write rows without pre-existing auth.users / organizations records.
-- RLS policies on the same tables enforce row-level isolation at the application level.
-- Service-role key bypasses RLS; the FKs would only block writes unnecessarily.

-- Drop constraints that require pre-existing auth.users / organizations rows
alter table public.daily_usage drop constraint if exists daily_usage_org_id_fkey;
alter table public.daily_usage drop constraint if exists daily_usage_user_id_fkey;
alter table public.investigations drop constraint if exists investigations_org_id_fkey;
alter table public.investigations drop constraint if exists investigations_user_id_fkey;

-- Allow NULLs on the formerly-FK columns (backwards compatible)
alter table public.daily_usage alter column org_id drop not null;
alter table public.daily_usage alter column user_id drop not null;
alter table public.investigations alter column org_id drop not null;
alter table public.investigations alter column user_id drop not null;

-- Seed a default dev-org + dev-user so anonymous dev-mode writes succeed.
-- These UUIDs must match the ones the security layer uses for the dev fallback.
do $$
declare
  _dev_org_id uuid := '00000000-0000-0000-0000-000000000001'::uuid;
  _dev_user_id uuid := '00000000-0000-0000-0000-000000000002'::uuid;
  _dev_org_exists boolean;
  _dev_user_exists boolean;
begin
  -- Create a stub auth.users entry for dev-user (Supabase Auth needs this for FK)
  select exists (select 1 from auth.users where id = _dev_user_id) into _dev_user_exists;
  if not _dev_user_exists then
    insert into auth.users (id, email, encrypted_password, created_at, updated_at, last_sign_in_at)
    values (_dev_user_id, 'dev@local', '___placeholder___', now(), now(), now())
    on conflict (id) do nothing;
  end if;

  -- Create a stub organization
  select exists (select 1 from organizations where id = _dev_org_id) into _dev_org_exists;
  if not _dev_org_exists then
    insert into organizations (id, name, slug, plan, daily_free_quota, created_at)
    values (_dev_org_id, 'Local Dev', 'dev-org', 'community', 100, now())
    on conflict (id) do nothing;
  end if;

  -- Optionally link dev-user to dev-org
  if not exists (
    select 1 from organization_members
    where org_id = _dev_org_id and user_id = _dev_user_id
  ) then
    insert into organization_members (org_id, user_id, role, status, created_at, updated_at)
    values (_dev_org_id, _dev_user_id, 'admin', 'active', now(), now())
    on conflict do nothing;
  end if;
end $$;

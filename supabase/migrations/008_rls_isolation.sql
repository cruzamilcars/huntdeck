-- 008_rls_isolation.sql
-- Enable Row Level Security on all core tables and attach per-tenant
-- policies so authenticated users can only see their own rows.
-- The service role bypasses RLS (used by the backend for management).

-- Enable RLS
alter table public.investigations enable row level security;
alter table public.watchlist enable row level security;
alter table public.daily_usage enable row level security;
alter table public.organizations enable row level security;
alter table public.organization_members enable row level security;
alter table public.profiles enable row level security;

-- Investigations: read/write own rows only
drop policy if exists "investigations_select_own" on public.investigations;
create policy "investigations_select_own" on public.investigations
  for select using (auth.role() = 'service_role' or auth.uid() = user_id);

drop policy if exists "investigations_insert_own" on public.investigations;
create policy "investigations_insert_own" on public.investigations
  for insert with check (auth.role() = 'service_role' or auth.uid() = user_id);

drop policy if exists "investigations_update_own" on public.investigations;
create policy "investigations_update_own" on public.investigations
  for update using (auth.role() = 'service_role' or auth.uid() = user_id);

-- Watchlist: full CRUD own rows
drop policy if exists "watchlist_select_own" on public.watchlist;
create policy "watchlist_select_own" on public.watchlist
  for select using (auth.role() = 'service_role' or auth.uid() = user_id);

drop policy if exists "watchlist_insert_own" on public.watchlist;
create policy "watchlist_insert_own" on public.watchlist
  for insert with check (auth.role() = 'service_role' or auth.uid() = user_id);

drop policy if exists "watchlist_delete_own" on public.watchlist;
create policy "watchlist_delete_own" on public.watchlist
  for delete using (auth.role() = 'service_role' or auth.uid() = user_id);

drop policy if exists "watchlist_update_own" on public.watchlist;
create policy "watchlist_update_own" on public.watchlist
  for update using (auth.role() = 'service_role' or auth.uid() = user_id);

-- Daily usage: own quota rows
drop policy if exists "daily_usage_select_own" on public.daily_usage;
create policy "daily_usage_select_own" on public.daily_usage
  for select using (auth.role() = 'service_role' or auth.uid() = user_id);

drop policy if exists "daily_usage_insert_own" on public.daily_usage;
create policy "daily_usage_insert_own" on public.daily_usage
  for insert with check (auth.role() = 'service_role' or auth.uid() = user_id);

drop policy if exists "daily_usage_update_own" on public.daily_usage;
create policy "daily_usage_update_own" on public.daily_usage
  for update using (auth.role() = 'service_role' or auth.uid() = user_id);

-- Organizations: members see their orgs
drop policy if exists "organizations_select_member" on public.organizations;
create policy "organizations_select_member" on public.organizations
  for select using (
    auth.role() = 'service_role'
    or exists (select 1 from public.organization_members om where om.org_id = organizations.id and om.user_id = auth.uid())
  );

-- Organization members: members see their org's members
drop policy if exists "org_members_select_own_org" on public.organization_members;
create policy "org_members_select_own_org" on public.organization_members
  for select using (
    auth.role() = 'service_role'
    or exists (select 1 from public.organization_members my where my.org_id = organization_members.org_id and my.user_id = auth.uid())
  );

-- Profiles: own profile
drop policy if exists "profiles_select_own" on public.profiles;
create policy "profiles_select_own" on public.profiles
  for select using (auth.role() = 'service_role' or auth.uid() = id);

drop policy if exists "profiles_update_own" on public.profiles;
create policy "profiles_update_own" on public.profiles
  for update using (auth.role() = 'service_role' or auth.uid() = id);
-- OSINT MCP Hub: watchlist of IOCs for periodic re-investigation.

create table if not exists public.watchlist (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  raw_ioc text not null check (char_length(raw_ioc) between 1 and 4096),
  normalized_ioc text not null,
  ioc_type public.ioc_type not null default 'unknown',
  note text,
  created_at timestamptz not null default now(),
  last_checked_at timestamptz,
  last_risk_score integer check (last_risk_score is null or last_risk_score between 0 and 100),
  last_severity text check (
    last_severity is null
    or last_severity in ('unknown', 'low', 'medium', 'high', 'critical')
  ),
  unique (org_id, user_id, normalized_ioc)
);

create index if not exists watchlist_scope_idx
  on public.watchlist(org_id, user_id, created_at desc);

alter table public.watchlist enable row level security;

drop policy if exists "watchlist_select_own" on public.watchlist;
create policy "watchlist_select_own"
on public.watchlist
for select
to authenticated
using ((select auth.uid()) = user_id);

drop policy if exists "watchlist_insert_own" on public.watchlist;
create policy "watchlist_insert_own"
on public.watchlist
for insert
to authenticated
with check (
  (select auth.uid()) = user_id
  and (org_id is null or (select private.is_org_member(org_id)))
);

drop policy if exists "watchlist_update_own" on public.watchlist;
create policy "watchlist_update_own"
on public.watchlist
for update
to authenticated
using ((select auth.uid()) = user_id)
with check ((select auth.uid()) = user_id);

drop policy if exists "watchlist_delete_own" on public.watchlist;
create policy "watchlist_delete_own"
on public.watchlist
for delete
to authenticated
using ((select auth.uid()) = user_id);
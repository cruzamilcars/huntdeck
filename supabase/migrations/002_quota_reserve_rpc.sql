-- OSINT MCP Hub: atomic daily quota reservation.
-- Moved to SQL instead of read-then-write from the API so concurrent
-- requests cannot double-spend the free quota (row lock via SELECT ... FOR UPDATE).

create or replace function public.reserve_daily_usage(
  p_org_id uuid,
  p_user_id uuid,
  p_usage_date date,
  p_daily_free_quota integer,
  p_byok_providers text[]
)
returns table (
  allowed boolean,
  used_byok boolean,
  free_queries_used integer,
  byok_queries_used integer,
  reason text
)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_free integer;
  v_byok integer;
begin
  if p_org_id is null or p_user_id is null then
    raise exception 'org_id and user_id are required';
  end if;

  select free_queries_used, byok_queries_used
    into v_free, v_byok
  from public.daily_usage
  where org_id = p_org_id and user_id = p_user_id and usage_date = p_usage_date
  for update;

  if v_free is null then
    insert into public.daily_usage (org_id, user_id, usage_date, free_queries_used, byok_queries_used)
    values (p_org_id, p_user_id, p_usage_date, 0, 0);
    v_free := 0;
    v_byok := 0;
  end if;

  if v_free < p_daily_free_quota then
    v_free := v_free + 1;
    update public.daily_usage
      set free_queries_used = v_free, updated_at = now()
    where org_id = p_org_id and user_id = p_user_id and usage_date = p_usage_date;
    return query
      select true, false, v_free, v_byok, 'platform_quota'::text;
  elsif p_byok_providers is not null and cardinality(p_byok_providers) > 0 then
    v_byok := v_byok + 1;
    update public.daily_usage
      set byok_queries_used = v_byok, updated_at = now()
    where org_id = p_org_id and user_id = p_user_id and usage_date = p_usage_date;
    return query
      select true, true, v_free, v_byok, 'byok'::text;
  else
    return query
      select false, false, v_free, v_byok, 'quota_exhausted'::text;
  end if;
end;
$$;

revoke all on function public.reserve_daily_usage(uuid, uuid, date, integer, text[]) from anon;
grant execute on function public.reserve_daily_usage(uuid, uuid, date, integer, text[]) to authenticated, service_role;
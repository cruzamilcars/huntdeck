-- 009_retention_ttl.sql
-- Add functions and notes for data retention TTL (time-to-live).
-- Old investigations and daily_usage rows should be deleted periodically
-- to comply with data retention policies and control storage growth.

-- Function to delete old investigations (older than retention_days)
create or replace function public.delete_old_investigations(retention_days integer default 90)
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
  deleted_count integer;
begin
  delete from public.investigations
  where created_at < now() - (retention_days || ' days')::interval
  returning 1 into deleted_count;

  get diagnostics deleted_count = row_count;
  return coalesce(deleted_count, 0);
end;
$$;

-- Function to delete old daily_usage rows (older than retention_days)
create or replace function public.delete_old_daily_usage(retention_days integer default 90)
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
  deleted_count integer;
begin
  delete from public.daily_usage
  where updated_at < now() - (retention_days || ' days')::interval
  returning 1 into deleted_count;

  get diagnostics deleted_count = row_count;
  return coalesce(deleted_count, 0);
end;
$$;

-- Function to delete old watchlist entries (older than retention_days)
create or replace function public.delete_old_watchlist(retention_days integer default 90)
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
  deleted_count integer;
begin
  delete from public.watchlist
  where updated_at < now() - (retention_days || ' days')::interval
  returning 1 into deleted_count;

  get diagnostics deleted_count = row_count;
  return coalesce(deleted_count, 0);
end;
$$;

-- Grant execute on these functions to authenticated users and service role
grant execute on function public.delete_old_investigations(integer) to authenticated, service_role;
grant execute on function public.delete_old_daily_usage(integer) to authenticated, service_role;
grant execute on function public.delete_old_watchlist(integer) to authenticated, service_role;

-- Note: These functions should be called periodically (e.g. daily via cron)
-- to enforce data retention policies. Example usage:
-- SELECT public.delete_old_investigations(90);
-- SELECT public.delete_old_daily_usage(90);
-- SELECT public.delete_old_watchlist(90);
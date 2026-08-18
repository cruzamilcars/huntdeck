-- OSINT MCP Hub: extend IOC types with social media handles.
-- Must run after 001_initial_schema.sql (which creates public.ioc_type).

do $$
begin
  alter type public.ioc_type add value if not exists 'social_handle';
end $$;
export interface SessionContext {
  accessToken: string | null;
  email: string | null;
  orgId: string | null;
}

export async function getSessionContext(): Promise<SessionContext> {
  if (!process.env.NEXT_PUBLIC_SUPABASE_URL || !process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY) {
    return { accessToken: null, email: null, orgId: null };
  }

  const { createClient } = await import("@/lib/supabase/client");
  const {
    data: { session },
  } = await createClient().auth.getSession();

  if (!session) {
    return { accessToken: null, email: null, orgId: null };
  }

  const metadata = session.user.user_metadata as Record<string, unknown> | undefined;
  const orgId =
    typeof metadata?.default_org_id === "string" ? metadata.default_org_id : null;

  return {
    accessToken: session.access_token,
    email: session.user.email ?? null,
    orgId,
  };
}
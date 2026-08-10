"use client";

import { AlertTriangle, ArrowRight, Loader2 } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { FormEvent, useState } from "react";

import { isSupabaseConfigured } from "@/lib/supabase/client";

export default function RegisterPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  if (!isSupabaseConfigured) {
    return (
      <div className="muted-panel p-6 text-center">
        <AlertTriangle className="mx-auto mb-4 text-[var(--warning)]" size={32} />
        <p className="text-sm font-bold uppercase">Supabase not configured</p>
        <p className="mt-3 text-xs text-[var(--muted)]">
          Set NEXT_PUBLIC_SUPABASE_URL and NEXT_PUBLIC_SUPABASE_ANON_KEY to enable
          registration.
        </p>
      </div>
    );
  }

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true);
    setError(null);
    setMessage(null);
    try {
      const { createClient } = await import("@/lib/supabase/client");
      const { data, error: signUpError } = await createClient().auth.signUp({
        email,
        password,
      });
      if (signUpError) {
        setError(signUpError.message);
        return;
      }
      if (data.session) {
        router.push("/investigate");
        router.refresh();
      } else {
        setMessage("Check your inbox to confirm your email, then sign in.");
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <form onSubmit={onSubmit} className="brutal-panel p-6">
      <label htmlFor="email" className="mb-2 block text-xs uppercase text-[var(--muted)]">
        Email
      </label>
      <input
        id="email"
        type="email"
        value={email}
        onChange={(event) => setEmail(event.target.value)}
        required
        className="mb-4 h-12 w-full border border-[var(--muted-line)] bg-black px-3 text-white outline-none focus:border-[var(--line)]"
        autoComplete="email"
      />

      <label htmlFor="password" className="mb-2 block text-xs uppercase text-[var(--muted)]">
        Password
      </label>
      <input
        id="password"
        type="password"
        value={password}
        onChange={(event) => setPassword(event.target.value)}
        required
        minLength={8}
        className="mb-6 h-12 w-full border border-[var(--muted-line)] bg-black px-3 text-white outline-none focus:border-[var(--line)]"
        autoComplete="new-password"
      />

      {error ? (
        <p className="mb-4 flex items-start gap-2 border border-[var(--danger)] bg-black p-3 text-xs uppercase text-[var(--danger)]">
          <AlertTriangle size={14} className="mt-0.5 shrink-0" />
          {error}
        </p>
      ) : null}

      {message ? (
        <p className="mb-4 border border-[var(--ok)] bg-black p-3 text-xs uppercase text-[var(--ok)]">
          {message}
        </p>
      ) : null}

      <button
        type="submit"
        disabled={loading}
        className="flex h-12 w-full items-center justify-center gap-2 border border-[var(--line)] bg-[var(--line)] px-4 font-black uppercase text-black disabled:bg-[var(--panel-2)] disabled:text-[var(--muted)]"
      >
        {loading ? <Loader2 size={16} className="animate-spin" /> : <ArrowRight size={16} />}
        Create account
      </button>

      <p className="mt-4 text-center text-xs uppercase text-[var(--muted)]">
        Already registered?{" "}
        <Link href="/login" className="text-[var(--warning)] underline">
          Sign in
        </Link>
      </p>
    </form>
  );
}
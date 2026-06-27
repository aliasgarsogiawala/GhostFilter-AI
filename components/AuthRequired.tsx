"use client";

import { FormEvent, useState } from "react";
import { signIn } from "next-auth/react";
import { LockKeyhole, ShieldCheck } from "lucide-react";

export function AuthRequired({ title = "Sign in to GhostFilter" }: { title?: string }) {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setLoading(true);
    const result = await signIn("credentials", {
      name,
      email,
      password,
      redirect: false,
    });
    setLoading(false);
    if (result?.error) setError("Sign-in failed. Check your email and access code.");
  }

  return (
    <main className="min-h-screen bg-[var(--ink)] px-5 py-10 text-zinc-300">
      <section className="mx-auto flex min-h-[calc(100vh-80px)] max-w-md items-center">
        <form onSubmit={submit} className="w-full rounded-lg border border-[var(--line-strong)] bg-[var(--panel)] p-5 shadow-[4px_4px_0_0_#050507]">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-md border border-[var(--line-strong)] bg-[var(--input)] text-[var(--accent)]">
              <ShieldCheck className="h-5 w-5" />
            </div>
            <div>
              <h1 className="text-lg font-semibold text-zinc-100">{title}</h1>
              <p className="mt-1 text-xs leading-5 text-zinc-500">
                Scans, connections, and history are tied to your authenticated session.
              </p>
            </div>
          </div>

          <label className="mt-5 block text-[11px] font-semibold text-zinc-400">
            Name
            <input
              value={name}
              onChange={(event) => setName(event.target.value)}
              className="mt-1 h-10 w-full rounded-md border border-[var(--line)] bg-[var(--input)] px-3 text-sm text-zinc-100"
              placeholder="Your name"
            />
          </label>
          <label className="mt-3 block text-[11px] font-semibold text-zinc-400">
            Email
            <input
              required
              type="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              className="mt-1 h-10 w-full rounded-md border border-[var(--line)] bg-[var(--input)] px-3 text-sm text-zinc-100"
              placeholder="you@example.com"
            />
          </label>
          <label className="mt-3 block text-[11px] font-semibold text-zinc-400">
            Access code
            <input
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              className="mt-1 h-10 w-full rounded-md border border-[var(--line)] bg-[var(--input)] px-3 text-sm text-zinc-100"
              placeholder="Hackathon access code"
            />
          </label>
          {error && <p className="mt-3 text-xs text-[var(--danger)]">{error}</p>}
          <button
            type="submit"
            disabled={loading}
            className="mt-5 flex h-10 w-full items-center justify-center gap-2 rounded-md bg-[var(--accent)] text-xs font-semibold text-[var(--accent-ink)] disabled:cursor-not-allowed disabled:opacity-60"
          >
            <LockKeyhole className="h-4 w-4" />
            {loading ? "Signing in..." : "Sign in"}
          </button>
        </form>
      </section>
    </main>
  );
}

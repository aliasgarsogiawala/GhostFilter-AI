"use client";

import { useSession } from "next-auth/react";

/** Stable authenticated owner id from NextAuth. */
export function useOwnerId(): string | null {
  const { data: session } = useSession();
  return session?.user?.id ?? null;
}

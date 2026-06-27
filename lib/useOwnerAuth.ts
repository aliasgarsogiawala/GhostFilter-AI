"use client";

import { useSession } from "next-auth/react";

export function useOwnerAuth() {
  const { data: session, status } = useSession();
  const ownerId = session?.user?.id ?? null;
  const ownerToken = session?.ownerToken ?? null;
  return {
    ownerId,
    ownerToken,
    status,
    args: ownerId && ownerToken ? { ownerId, ownerToken } : null,
  };
}

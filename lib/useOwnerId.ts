"use client";

import { useSyncExternalStore } from "react";

const STORAGE_KEY = "ghostfilter_owner_id";

function getSnapshot(): string | null {
  if (typeof window === "undefined") return null;
  let id = localStorage.getItem(STORAGE_KEY);
  if (!id) {
    id = crypto.randomUUID();
    localStorage.setItem(STORAGE_KEY, id);
  }
  return id;
}

function subscribe(callback: () => void): () => void {
  window.addEventListener("storage", callback);
  return () => window.removeEventListener("storage", callback);
}

function getServerSnapshot(): string | null {
  return null;
}

/** Stable anonymous per-browser id — no auth system needed for the hackathon MVP. */
export function useOwnerId(): string | null {
  return useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);
}

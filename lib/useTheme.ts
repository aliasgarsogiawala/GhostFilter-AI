"use client";

import { useEffect, useSyncExternalStore } from "react";

const KEY = "gf_theme";

// Background themes — these change the page/surface palette, not the accent.
export const THEMES = [
  { id: "carbon", label: "Carbon", swatch: "#121217" },
  { id: "midnight", label: "Midnight", swatch: "#0f1422" },
  { id: "obsidian", label: "Obsidian", swatch: "#0b0b0d" },
  { id: "graphite", label: "Graphite", swatch: "#1a1917" },
  { id: "forest", label: "Forest", swatch: "#111815" },
] as const;

export type ThemeId = (typeof THEMES)[number]["id"];

const VALID = new Set(THEMES.map((t) => t.id));

function apply(theme: string) {
  if (typeof document !== "undefined") {
    document.documentElement.setAttribute("data-theme", theme);
  }
}

const listeners = new Set<() => void>();

function getSnapshot(): ThemeId {
  if (typeof localStorage === "undefined") return "carbon";
  const t = localStorage.getItem(KEY);
  return t && VALID.has(t as ThemeId) ? (t as ThemeId) : "carbon";
}

function getServerSnapshot(): ThemeId {
  return "carbon";
}

function subscribe(cb: () => void) {
  listeners.add(cb);
  return () => listeners.delete(cb);
}

export function setTheme(theme: ThemeId) {
  localStorage.setItem(KEY, theme);
  apply(theme);
  listeners.forEach((l) => l());
}

/** Persisted accent theme. The effect applies it to <html data-theme> on mount and changes,
 *  so it survives navigation between the dashboard and profile pages. */
export function useTheme(): [ThemeId, (t: ThemeId) => void] {
  const theme = useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);
  useEffect(() => {
    apply(theme);
  }, [theme]);
  return [theme, setTheme];
}

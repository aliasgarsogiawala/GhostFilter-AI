"use client";

import { useEffect, useSyncExternalStore } from "react";

const KEY = "gf_theme";
const APPEARANCE_KEY = "gf_appearance";

// Background themes — these change the page/surface palette, not the accent.
export const THEMES = [
  { id: "carbon", label: "Carbon", swatch: "#667085" },
  { id: "midnight", label: "Midnight", swatch: "#5270d7" },
  { id: "obsidian", label: "Obsidian", swatch: "#27272e" },
  { id: "graphite", label: "Graphite", swatch: "#a66b45" },
  { id: "forest", label: "Forest", swatch: "#278666" },
] as const;

export type ThemeId = (typeof THEMES)[number]["id"];

const VALID = new Set(THEMES.map((t) => t.id));

function apply(theme: string) {
  if (typeof document !== "undefined") {
    document.documentElement.setAttribute("data-theme", theme);
  }
}

const listeners = new Set<() => void>();
const appearanceListeners = new Set<() => void>();

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

export type Appearance = "dark" | "light";

function applyAppearance(appearance: Appearance) {
  if (typeof document !== "undefined") {
    document.documentElement.setAttribute("data-appearance", appearance);
    document.documentElement.style.colorScheme = appearance;
  }
}

function getAppearanceSnapshot(): Appearance {
  if (typeof localStorage === "undefined") return "dark";
  return localStorage.getItem(APPEARANCE_KEY) === "light" ? "light" : "dark";
}

function subscribeAppearance(cb: () => void) {
  appearanceListeners.add(cb);
  return () => appearanceListeners.delete(cb);
}

export function setAppearance(appearance: Appearance) {
  localStorage.setItem(APPEARANCE_KEY, appearance);
  applyAppearance(appearance);
  appearanceListeners.forEach((listener) => listener());
}

export function useAppearance(): [Appearance, (appearance: Appearance) => void] {
  const appearance = useSyncExternalStore(
    subscribeAppearance,
    getAppearanceSnapshot,
    () => "dark" as Appearance
  );

  useEffect(() => {
    applyAppearance(appearance);
  }, [appearance]);

  return [appearance, setAppearance];
}

/**
 * Theme handling for the workspace.
 *
 * The preference is stored under one key so it survives reloads and navigation.
 * Until the user chooses explicitly, the operating-system preference decides,
 * and it keeps doing so if they never touch the toggle. An inline script in
 * index.html applies the same decision before first paint so there is no flash
 * of the wrong theme.
 */
import { useCallback, useEffect, useState } from "react";

export const THEME_KEY = "ava-theme";
export const THEMES = ["light", "dark"];

export function readStoredTheme() {
  try {
    const stored = window.localStorage.getItem(THEME_KEY);
    return THEMES.includes(stored) ? stored : null;
  } catch {
    return null; // storage can be unavailable (private mode, blocked cookies)
  }
}

export function systemTheme() {
  try {
    return window.matchMedia?.("(prefers-color-scheme: dark)").matches
      ? "dark"
      : "light";
  } catch {
    return "light";
  }
}

export function resolveTheme() {
  return readStoredTheme() || systemTheme();
}

export function applyTheme(theme) {
  const chosen = THEMES.includes(theme) ? theme : "light";
  document.documentElement.setAttribute("data-theme", chosen);
  document.documentElement.style.colorScheme = chosen;
  // Keep the browser chrome in step with the chosen theme rather than the OS.
  const chrome = document.querySelector('meta[name="theme-color"]');
  if (chrome) {
    chrome.setAttribute("content", chosen === "dark" ? "#121212" : "#f5f7f6");
  }
  return chosen;
}

export function storeTheme(theme) {
  try {
    window.localStorage.setItem(THEME_KEY, theme);
  } catch {
    /* preference simply does not persist; the theme still applies this session */
  }
}

export function useTheme() {
  const [theme, setTheme] = useState(resolveTheme);
  useEffect(() => {
    applyTheme(theme);
  }, [theme]);
  const toggle = useCallback(() => {
    setTheme((current) => {
      const next = current === "dark" ? "light" : "dark";
      storeTheme(next);
      return next;
    });
  }, []);
  return [theme, toggle];
}

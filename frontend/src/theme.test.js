import { readFileSync } from "node:fs";
import { beforeEach, describe, it, expect, vi } from "vitest";
import {
  THEME_KEY,
  applyTheme,
  readStoredTheme,
  resolveTheme,
  storeTheme,
} from "./theme";

beforeEach(() => {
  window.localStorage.clear();
  window.matchMedia = vi.fn().mockReturnValue({ matches: false });
});

describe("theme helpers", () => {
  it("reads and round-trips a stored preference", () => {
    expect(readStoredTheme()).toBeNull();
    storeTheme("dark");
    expect(window.localStorage.getItem(THEME_KEY)).toBe("dark");
    expect(readStoredTheme()).toBe("dark");
    storeTheme("light");
    expect(readStoredTheme()).toBe("light");
  });

  it("ignores an unrecognised stored value and uses the system preference", () => {
    window.localStorage.setItem(THEME_KEY, "banana");
    expect(readStoredTheme()).toBeNull();
    window.matchMedia = vi.fn().mockReturnValue({ matches: true });
    expect(resolveTheme()).toBe("dark");
  });

  it("applies the theme to the document element", () => {
    applyTheme("dark");
    expect(document.documentElement.getAttribute("data-theme")).toBe("dark");
    expect(document.documentElement.style.colorScheme).toBe("dark");
    applyTheme("light");
    expect(document.documentElement.getAttribute("data-theme")).toBe("light");
    expect(applyTheme("nonsense")).toBe("light"); // unknown values fail safe
  });

  it("still applies a theme when storage is unavailable", () => {
    const getItem = vi
      .spyOn(window.localStorage.__proto__, "getItem")
      .mockImplementation(() => {
        throw new Error("storage blocked");
      });
    const setItem = vi
      .spyOn(window.localStorage.__proto__, "setItem")
      .mockImplementation(() => {
        throw new Error("storage blocked");
      });
    try {
      expect(readStoredTheme()).toBeNull();
      expect(() => storeTheme("dark")).not.toThrow();
      expect(applyTheme("dark")).toBe("dark");
    } finally {
      getItem.mockRestore();
      setItem.mockRestore();
    }
  });
});

function tokenMap(css, selector) {
  const start = css.indexOf(selector + " {");
  const block = css.slice(start, css.indexOf("}", start));
  const map = {};
  for (const [, name, value] of block.matchAll(/--([\w-]+)\s*:\s*(#[0-9a-fA-F]{3,8})/g)) {
    map[name] = value;
  }
  return map;
}

function luminance(hex) {
  let h = hex.replace("#", "");
  if (h.length === 3) h = h.replace(/./g, (c) => c + c);
  const channel = (v) => {
    v /= 255;
    return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
  };
  const [r, g, b] = [0, 2, 4].map((i) => channel(parseInt(h.slice(i, i + 2), 16)));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrast(a, b) {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

// Text tokens checked against every surface they are rendered on. A palette
// regeneration that drops one of these below AA fails here instead of shipping.
const TEXT_ON_SURFACE = [
  ["t-green-1-t", "t-neutral-5-b"], // headings and body copy on the page
  ["t-green-1-t", "t-neutral-5-2-b"], // ... and on panels/cards
  ["t-green-3-t", "t-neutral-5-b"], // paragraph text
  ["t-green-3-t", "t-neutral-5-2-b"],
  ["t-green-3-t", "t-neutral-5-3-b"], // paragraph text on an inset/code surface
  ["t-green-3-12-t", "t-neutral-5-b"], // eyebrow labels
  ["t-neutral-3-t", "t-neutral-5-b"], // small muted text
  ["t-neutral-3-t", "t-neutral-5-2-b"],
  ["t-green-3-40-t", "t-green-1-6-b"], // sign-in art panel: paragraph
  ["t-green-3-41-t", "t-green-1-6-b"], // ... eyebrow
  ["t-green-3-43-t", "t-green-1-6-b"], // ... fine print
  ["t-green-3-3-t", "t-green-1-6-b"], // brand wordmark on the art panel
  ["t-green-3-3-t", "t-teal-1-b"], // ... and in the signed-in sidebar
];

describe("stylesheet theming", () => {
  const css = readFileSync("src/styles.css", "utf8");
  // Token declarations are the only place a raw colour may appear.
  const rules = css
    .split("\n")
    .filter((line) => !/^\s*--[\w-]+\s*:/.test(line))
    .join("\n");

  it("defines a dark palette alongside the light one", () => {
    expect(css).toContain('[data-theme="dark"]');
    expect(css).toMatch(/\[data-theme="dark"\]\s*\{[\s\S]*--t-/);
  });

  it.each(["light", "dark"])('meets WCAG AA for text in the %s theme', (theme) => {
    const light = tokenMap(css, ":root");
    const chosen = theme === "light" ? light : tokenMap(css, '[data-theme="dark"]');
    for (const [text, surface] of TEXT_ON_SURFACE) {
      const fg = chosen[text] || light[text];
      const bg = chosen[surface] || light[surface];
      expect(fg, `${theme}: missing --${text}`).toBeTruthy();
      expect(bg, `${theme}: missing --${surface}`).toBeTruthy();
      expect(
        contrast(fg, bg),
        `${theme}: --${text} on --${surface} is ${contrast(fg, bg).toFixed(2)}:1`,
      ).toBeGreaterThanOrEqual(4.5);
    }
  });

  it.each(["light", "dark"])(
    'meets WCAG AA for every rule pairing text with a surface in the %s theme',
    (theme) => {
      // Layout-free coverage of the signed-in shell (badges, table headers,
      // sidebar, topbar, alerts) which a browser audit of the sign-in view
      // cannot reach. Every rule that sets a text colour and a background on
      // the same element must clear 4.5:1 in both themes.
      const light = tokenMap(css, ":root");
      const chosen = theme === "light" ? light : tokenMap(css, '[data-theme="dark"]');
      const body = css.slice(css.indexOf("}", css.indexOf(":root {")) + 1);
      const pairs = [];
      for (const [, selector, decl] of body.matchAll(/([^{}]+)\{([^}]*)\}/g)) {
        const fg = decl.match(/(?<!-)color:\s*var\(--([\w-]+)\)/);
        const bg = decl.match(/background(?:-color)?:\s*var\(--([\w-]+)\)/);
        if (fg && bg) {
          pairs.push({ sel: selector.trim().replace(/\s+/g, " "), fg: fg[1], bg: bg[1] });
        }
      }
      expect(pairs.length).toBeGreaterThan(20);
      for (const { sel, fg, bg } of pairs) {
        const value = contrast(chosen[fg] || light[fg], chosen[bg] || light[bg]);
        expect(
          value,
          `${theme}: ${sel} --${fg} on --${bg} is ${value.toFixed(2)}:1`,
        ).toBeGreaterThanOrEqual(4.5);
      }
    },
  );

  it("has no hardcoded colour outside the token declarations", () => {
    // A literal colour in a rule is invisible to the theme switch: this guard
    // is what caught `background: white` on the sign-in field.
    const literals = rules.match(/#[0-9a-fA-F]{3,8}\b|\brgba?\(|\bhsla?\(/g) || [];
    expect(literals).toEqual([]);
    const named =
      rules.match(
        /(?<![\w-])(white|black|gray|grey|silver|red|blue|yellow|orange|purple|pink|brown|navy|teal|aqua|maroon|olive|lime|cyan|magenta|ivory|beige|khaki|coral|salmon|tan|crimson|indigo|violet|plum|orchid|azure|snow|linen|wheat)(?![\w-])/g,
      ) || [];
    expect(named).toEqual([]);
  });
});

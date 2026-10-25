// Applied before first paint so the stored theme never flashes.
// External (not inline) so the production CSP can keep script-src 'self'.
(function () {
  var theme = "light";
  try {
    var stored = window.localStorage.getItem("ava-theme");
    if (stored === "light" || stored === "dark") {
      theme = stored;
    } else if (window.matchMedia("(prefers-color-scheme: dark)").matches) {
      theme = "dark";
    }
  } catch (error) {
    /* storage unavailable: fall back to light */
  }
  document.documentElement.setAttribute("data-theme", theme);
  document.documentElement.style.colorScheme = theme;
  var chrome = document.querySelector('meta[name="theme-color"]');
  if (chrome) chrome.setAttribute("content", theme === "dark" ? "#121212" : "#f5f7f6");
})();

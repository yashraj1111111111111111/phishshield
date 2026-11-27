(function () {
  let guardEnabled = true;
  let tempAllow = {};

  function refreshSettings() {
    chrome.storage.local.get({ enabled: true, tempAllow: {} }, (stored) => {
      guardEnabled = Boolean(stored.enabled);
      tempAllow = stored.tempAllow || {};
    });
  }

  refreshSettings();
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== "local") return;
    if (changes.enabled) guardEnabled = Boolean(changes.enabled.newValue);
    if (changes.tempAllow) tempAllow = changes.tempAllow.newValue || {};
  });

  document.addEventListener(
    "click",
    (event) => {
      if (!guardEnabled || event.defaultPrevented || event.button !== 0) return;
      const anchor = event.target && event.target.closest ? event.target.closest("a[href]") : null;
      if (!anchor || !anchor.href) return;
      if (!/^https?:\/\//i.test(anchor.href)) return;

      const allowedUntil = tempAllow[anchor.href];
      if (typeof allowedUntil === "number" && allowedUntil > Date.now()) return;

      const scanner = globalThis.PhishShieldScanner;
      if (!scanner) return;

      const result = scanner.scanText(anchor.href);
      if (result.risk_score >= 25) {
        event.preventDefault();
        event.stopPropagation();
        chrome.runtime.sendMessage({
          type: "OPEN_WARNING",
          url: anchor.href,
          newTab: anchor.target === "_blank" || event.metaKey || event.ctrlKey,
        });
      }
    },
    true,
  );
})();

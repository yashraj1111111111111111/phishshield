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

  /* ── Soft dismissible toast for Suspicious (25–59) ───────────────────── */
  function showSuspiciousToast(url, score, openInNewTab) {
    // Remove any existing toast first
    const existing = document.getElementById("ps-toast");
    if (existing) existing.remove();

    const toast = document.createElement("div");
    toast.id = "ps-toast";
    toast.setAttribute("role", "alertdialog");
    toast.setAttribute("aria-label", "PhishShield suspicious link warning");
    toast.innerHTML = `
      <div class="ps-toast-inner">
        <span class="ps-toast-icon">⚠</span>
        <div class="ps-toast-body">
          <strong>Suspicious link (${score}/100)</strong>
          <span class="ps-toast-url">${url}</span>
        </div>
        <div class="ps-toast-actions">
          <button id="ps-toast-open" type="button">Open anyway</button>
          <button id="ps-toast-dismiss" type="button" aria-label="Dismiss">✕</button>
        </div>
      </div>
    `;

    // Inline critical styles so the toast works without an injected stylesheet
    Object.assign(toast.style, {
      position: "fixed",
      top: "16px",
      right: "16px",
      zIndex: "2147483647",
      maxWidth: "420px",
      width: "calc(100% - 32px)",
      background: "#09192c",
      border: "1px solid #c97d00",
      borderRadius: "12px",
      boxShadow: "0 8px 32px #00000080",
      fontFamily: "Inter,ui-sans-serif,system-ui,sans-serif",
      fontSize: "14px",
      color: "#e8edf8",
      padding: "0",
      animation: "ps-slide-in .22s ease",
    });

    // Inject keyframe once
    if (!document.getElementById("ps-toast-styles")) {
      const style = document.createElement("style");
      style.id = "ps-toast-styles";
      style.textContent = `
        @keyframes ps-slide-in {
          from { opacity:0; transform:translateY(-12px); }
          to   { opacity:1; transform:translateY(0); }
        }
        #ps-toast .ps-toast-inner {
          display:flex; align-items:flex-start; gap:10px; padding:14px;
        }
        #ps-toast .ps-toast-icon {
          font-size:1.4em; color:#ffce77; flex-shrink:0; line-height:1.2;
        }
        #ps-toast .ps-toast-body {
          flex:1; display:flex; flex-direction:column; gap:3px; min-width:0;
        }
        #ps-toast .ps-toast-body strong { color:#ffce77; font-size:.95em; }
        #ps-toast .ps-toast-url {
          color:#8fa3bf; font-size:.78em; white-space:nowrap;
          overflow:hidden; text-overflow:ellipsis;
        }
        #ps-toast .ps-toast-actions {
          display:flex; gap:6px; flex-shrink:0; align-items:flex-start;
        }
        #ps-toast button {
          font:inherit; border-radius:8px; border:0; cursor:pointer;
          font-weight:700; padding:6px 10px; font-size:.8em; white-space:nowrap;
        }
        #ps-toast #ps-toast-open {
          background:transparent; color:#ffce77; border:1px solid #6b520a;
        }
        #ps-toast #ps-toast-dismiss {
          background:transparent; color:#8fa3bf; border:1px solid #223952;
        }
      `;
      document.head.appendChild(style);
    }

    document.body.appendChild(toast);

    let autoDismissTimer = setTimeout(() => toast.remove(), 15000);

    document.getElementById("ps-toast-dismiss").addEventListener("click", () => {
      clearTimeout(autoDismissTimer);
      toast.remove();
    });

    document.getElementById("ps-toast-open").addEventListener("click", () => {
      clearTimeout(autoDismissTimer);
      toast.remove();
      chrome.runtime.sendMessage({ type: "ALLOW_URL_ONCE", url }, () => {
        if (openInNewTab) {
          window.open(url, "_blank", "noopener,noreferrer");
        } else {
          window.location.href = url;
        }
      });
    });
  }

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
      const isNewTab = anchor.target === "_blank" || event.metaKey || event.ctrlKey;

      if (result.risk_score >= 60) {
        // Dangerous → full-page warning.html block
        event.preventDefault();
        event.stopPropagation();
        chrome.runtime.sendMessage({
          type: "OPEN_WARNING",
          url: anchor.href,
          newTab: isNewTab,
        });
      } else if (result.risk_score >= 25) {
        // Suspicious → soft dismissible in-page toast
        event.preventDefault();
        event.stopPropagation();
        showSuspiciousToast(anchor.href, result.risk_score, isNewTab);
      }
    },
    true,
  );

  /* ── Hover guard for deceptive anchor text vs href mismatch ───────────── */
  function showHoverBadge(label) {
    let badge = document.getElementById("ps-hover-badge");
    if (!badge) {
      badge = document.createElement("div");
      badge.id = "ps-hover-badge";
      Object.assign(badge.style, {
        position: "fixed",
        bottom: "16px",
        right: "16px",
        zIndex: "2147483646",
        background: "#09192c",
        color: "#ffce77",
        border: "1px solid #c97d00",
        borderRadius: "10px",
        padding: "8px 12px",
        fontFamily: "Inter,ui-sans-serif,system-ui,sans-serif",
        fontSize: "12px",
        fontWeight: "600",
        boxShadow: "0 6px 20px rgba(0,0,0,0.45)",
        pointerEvents: "none",
      });
      document.body.appendChild(badge);
    }
    badge.textContent = label;
  }

  function hideHoverBadge() {
    const badge = document.getElementById("ps-hover-badge");
    if (badge) badge.remove();
  }

  document.addEventListener("mouseover", (event) => {
    if (!guardEnabled) return;
    const anchor = event.target && event.target.closest ? event.target.closest("a[href]") : null;
    if (!anchor || !anchor.href || !/^https?:\/\//i.test(anchor.href)) return;
    const scanner = globalThis.PhishShieldScanner;
    if (!scanner) return;
    const mismatch = scanner.checkLinkTextMismatch ? scanner.checkLinkTextMismatch(anchor.textContent, anchor.href) : { mismatch: false };
    if (mismatch.mismatch) {
      showHoverBadge(`⚠ PhishShield: Link says "${mismatch.visibleDomain}" but goes to "${mismatch.targetHost}"`);
      return;
    }
    const res = scanner.scanText(anchor.href);
    if (res.risk_score >= 25) {
      showHoverBadge(`⚠ PhishShield: ${res.risk_level} link (${res.risk_score}/100)`);
    }
  });

  document.addEventListener("mouseout", (event) => {
    const anchor = event.target && event.target.closest ? event.target.closest("a[href]") : null;
    if (anchor) hideHoverBadge();
  });

  /* ── Paste guard for WhatsApp Web / Gmail / forms ─────────────────────── */
  document.addEventListener("paste", (event) => {
    if (!guardEnabled) return;
    const pasted = event.clipboardData && event.clipboardData.getData("text");
    if (!pasted || pasted.trim().length < 5) return;
    const scanner = globalThis.PhishShieldScanner;
    if (!scanner) return;
    const res = scanner.scanText(pasted);
    if (res.risk_score >= 25) {
      showSuspiciousToast(`Pasted ${res.risk_level} content: ${pasted.trim().slice(0, 60)}`, res.risk_score, false);
    }
  });
})();

(function () {
  const params = new URLSearchParams(window.location.search);
  const targetUrl = params.get("url") || "";
  const sourceUrl = params.get("from") || "";
  const isSoft = params.get("soft") === "1";  // true for Suspicious address-bar navigations

  const urlBox = document.getElementById("target-url");
  const verdictEl = document.getElementById("verdict");
  const meterEl = document.getElementById("meter-fill");
  const refEl = document.getElementById("scan-ref");
  const campaignEl = document.getElementById("campaign-badge");
  const reasonsEl = document.getElementById("reasons");
  const mlEl = document.getElementById("ml-signal");
  const explanationEl = document.getElementById("explanation");
  const langSelect = document.getElementById("language");
  const backBtn = document.getElementById("back-btn");
  const proceedBtn = document.getElementById("proceed-btn");

  urlBox.textContent = targetUrl || "(No URL provided)";

  // Soft mode: make it clear the user can proceed freely and swap button prominence
  if (isSoft) {
    document.querySelector("h1").textContent = "Heads up — this link looks suspicious.";
    document.querySelector(".subtitle").textContent =
      "PhishShield flagged this link as potentially suspicious. You can still proceed — this is an advisory notice only.";
    // Swap visual weight: proceed is now the primary action
    proceedBtn.className = "btn-primary";
    backBtn.className = "btn-secondary";
    proceedBtn.textContent = "Open link";
    backBtn.textContent = "← Take me back";
  }

  function renderResult(data) {
    const level = data.risk_level || "Suspicious";
    const cssLevel = level.toLowerCase().replace(/\s+/g, "-");
    const displayLevel = level === "Low Risk" ? "Low Risk (Unverified)" : level;
    const score = data.risk_score ?? 0;
    verdictEl.textContent = `${displayLevel} (${score}/100)`;
    verdictEl.className = `verdict ${cssLevel}`;
    meterEl.className = `meter-fill ${cssLevel}`;
    meterEl.style.width = `${Math.max(4, score)}%`;
    refEl.textContent = data.scan_reference ? `SCAN REF: ${data.scan_reference}` : "LOCAL CHECK";
    campaignEl.hidden = !data.campaign_detected;

    reasonsEl.replaceChildren();
    for (const reason of data.reasons || []) {
      const li = document.createElement("li");
      li.textContent = reason;
      reasonsEl.appendChild(li);
    }

    if (typeof data.ml_probability === "number") {
      mlEl.hidden = false;
      mlEl.textContent = `ML confidence signal: ${(data.ml_probability * 100).toFixed(1)}% phishing similarity (supporting evidence only)`;
    } else {
      mlEl.hidden = true;
    }

    explanationEl.textContent =
      data.explanation || "Review the indicators carefully before deciding whether to open this link.";
  }

  function runScan(language) {
    if (!targetUrl) return;
    const localResult = globalThis.PhishShieldScanner.scanText(targetUrl);
    renderResult(localResult);
    chrome.runtime.sendMessage(
      { type: "SCAN_WITH_API", content: targetUrl, language },
      (response) => {
        if (chrome.runtime.lastError || !response) return;
        renderResult(response);
      },
    );
  }

  chrome.storage.local.get({ language: "en" }, (stored) => {
    langSelect.value = stored.language || "en";
    runScan(langSelect.value);
  });

  langSelect.addEventListener("change", () => {
    chrome.storage.local.set({ language: langSelect.value });
    runScan(langSelect.value);
  });

  backBtn.addEventListener("click", () => {
    if (sourceUrl && /^https?:\/\//i.test(sourceUrl)) {
      window.location.href = sourceUrl;
      return;
    }
    if (window.history.length > 1) {
      window.history.back();
      return;
    }
    window.close();
  });

  proceedBtn.addEventListener("click", () => {
    if (!/^https?:\/\//i.test(targetUrl)) return;
    chrome.runtime.sendMessage({ type: "ALLOW_URL_ONCE", url: targetUrl }, () => {
      window.location.href = targetUrl;
    });
  });
})();

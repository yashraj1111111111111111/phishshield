(function () {
  const params = new URLSearchParams(window.location.search);
  const targetUrl = params.get("url") || "";
  const sourceUrl = params.get("from") || "";

  const urlBox = document.getElementById("target-url");
  const verdictEl = document.getElementById("verdict");
  const refEl = document.getElementById("scan-ref");
  const campaignEl = document.getElementById("campaign-badge");
  const reasonsEl = document.getElementById("reasons");
  const mlEl = document.getElementById("ml-signal");
  const explanationEl = document.getElementById("explanation");
  const langSelect = document.getElementById("language");
  const backBtn = document.getElementById("back-btn");
  const proceedBtn = document.getElementById("proceed-btn");

  urlBox.textContent = targetUrl || "(No URL provided)";

  function renderResult(data) {
    const level = data.risk_level || "Suspicious";
    verdictEl.textContent = `${level} (${data.risk_score ?? 0}/100)`;
    verdictEl.className = `verdict ${level.toLowerCase()}`;
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

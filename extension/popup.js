(function () {
  const toggleEl = document.getElementById("guard-toggle");
  const formEl = document.getElementById("scan-form");
  const inputEl = document.getElementById("scan-input");
  const langEl = document.getElementById("language");
  const scanBtn = document.getElementById("scan-btn");
  const errorEl = document.getElementById("error");
  const resultEl = document.getElementById("result");
  const verdictEl = document.getElementById("verdict");
  const meterEl = document.getElementById("meter-fill");
  const refEl = document.getElementById("scan-ref");
  const campaignEl = document.getElementById("campaign-badge");
  const reasonsEl = document.getElementById("reasons");
  const mlEl = document.getElementById("ml-signal");
  const explanationEl = document.getElementById("explanation");

  chrome.storage.local.get({ enabled: true, language: "en" }, (stored) => {
    toggleEl.checked = Boolean(stored.enabled);
    langEl.value = stored.language || "en";
  });

  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const activeUrl = tabs && tabs[0] && tabs[0].url ? tabs[0].url : "";
    if (/^https?:\/\//i.test(activeUrl) && !inputEl.value) {
      inputEl.value = activeUrl;
    }
  });

  toggleEl.addEventListener("change", () => {
    chrome.storage.local.set({ enabled: toggleEl.checked });
  });

  langEl.addEventListener("change", () => {
    chrome.storage.local.set({ language: langEl.value });
  });

  function renderResult(data) {
    resultEl.hidden = false;
    const level = data.risk_level || "Low Risk";
    const cssLevel = level.toLowerCase().replace(/\s+/g, "-");
    const displayLevel = level === "Low Risk" ? "Low Risk (Unverified)" : level;
    const score = data.risk_score ?? 0;
    verdictEl.textContent = `${displayLevel} (${score}/100)`;
    verdictEl.className = `verdict ${cssLevel}`;
    meterEl.className = `meter-fill ${cssLevel}`;
    meterEl.style.width = `${Math.max(4, score)}%`;
    refEl.textContent = data.scan_reference || "LOCAL";
    campaignEl.hidden = !data.campaign_detected;

    reasonsEl.replaceChildren();
    for (const reason of data.reasons || []) {
      const li = document.createElement("li");
      li.textContent = reason;
      reasonsEl.appendChild(li);
    }

    if (typeof data.ml_probability === "number") {
      mlEl.hidden = false;
      mlEl.textContent = `ML signal: ${(data.ml_probability * 100).toFixed(1)}% similarity`;
    } else {
      mlEl.hidden = true;
    }
    explanationEl.textContent = data.explanation || "";
  }

  formEl.addEventListener("submit", (event) => {
    event.preventDefault();
    const content = inputEl.value.trim();
    errorEl.hidden = true;
    if (content.length < 3) {
      errorEl.textContent = "Please enter at least 3 characters.";
      errorEl.hidden = false;
      return;
    }

    scanBtn.disabled = true;
    scanBtn.textContent = "Checking…";
    chrome.runtime.sendMessage(
      { type: "SCAN_WITH_API", content, language: langEl.value },
      (response) => {
        scanBtn.disabled = false;
        scanBtn.textContent = "Check safely";
        if (chrome.runtime.lastError || !response) {
          renderResult(globalThis.PhishShieldScanner.scanText(content));
          return;
        }
        renderResult(response);
      },
    );
  });
})();

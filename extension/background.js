importScripts("scanner.js");

const DEFAULT_API_URL = "http://127.0.0.1:8001";
const ALLOW_TTL_MS = 60_000;

async function getSettings() {
  const stored = await chrome.storage.local.get({
    enabled: true,
    apiUrl: DEFAULT_API_URL,
    language: "en",
    tempAllow: {},
  });
  return stored;
}

function buildWarningUrl(targetUrl, sourceUrl = "") {
  const params = new URLSearchParams({ url: targetUrl });
  if (sourceUrl) params.set("from", sourceUrl);
  return chrome.runtime.getURL(`warning.html?${params.toString()}`);
}

async function isTemporarilyAllowed(url) {
  const { tempAllow } = await getSettings();
  const expiresAt = tempAllow[url];
  return typeof expiresAt === "number" && expiresAt > Date.now();
}

async function allowUrlTemporarily(url) {
  const { tempAllow } = await getSettings();
  const now = Date.now();
  const pruned = {};
  for (const [key, exp] of Object.entries(tempAllow)) {
    if (typeof exp === "number" && exp > now) pruned[key] = exp;
  }
  pruned[url] = now + ALLOW_TTL_MS;
  await chrome.storage.local.set({ tempAllow: pruned });
}

async function scanWithBackend(content, languageOverride) {
  const settings = await getSettings();
  const language = languageOverride || settings.language || "en";
  const apiUrl = (settings.apiUrl || DEFAULT_API_URL).replace(/\/+$/, "");
  const localResult = globalThis.PhishShieldScanner.scanText(content);

  try {
    const response = await fetch(`${apiUrl}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content, language }),
    });
    const data = await response.json();
    if (!response.ok) {
      return {
        ...localResult,
        explanation: data.detail || "PhishShield API returned an error; showing local rule check.",
        api_available: false,
      };
    }
    return { ...data, api_available: true };
  } catch {
    return {
      ...localResult,
      scan_reference: "LOCAL-ONLY",
      explanation:
        language === "hi"
          ? `स्थानीय जांच के अनुसार यह ${localResult.risk_level} है। बिना सत्यापन लिंक न खोलें।`
          : `Local browser check rated this ${localResult.risk_level}. Start the PhishShield API for ML and AI explanations.`,
      ml_probability: null,
      campaign_detected: false,
      api_available: false,
    };
  }
}

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;
  if (!/^https?:\/\//i.test(details.url)) return;

  const settings = await getSettings();
  if (!settings.enabled) return;
  if (await isTemporarilyAllowed(details.url)) return;

  const localResult = globalThis.PhishShieldScanner.scanText(details.url);
  if (localResult.risk_score >= 25) {
    await chrome.tabs.update(details.tabId, { url: buildWarningUrl(details.url) });
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || typeof message !== "object") return false;

  if (message.type === "OPEN_WARNING") {
    const warningUrl = buildWarningUrl(message.url, sender.tab?.url || "");
    if (message.newTab || !sender.tab?.id) {
      chrome.tabs.create({ url: warningUrl });
    } else {
      chrome.tabs.update(sender.tab.id, { url: warningUrl });
    }
    sendResponse({ ok: true });
    return false;
  }

  if (message.type === "ALLOW_URL_ONCE") {
    allowUrlTemporarily(message.url).then(() => sendResponse({ ok: true }));
    return true;
  }

  if (message.type === "SCAN_WITH_API") {
    scanWithBackend(message.content, message.language).then(sendResponse);
    return true;
  }

  return false;
});

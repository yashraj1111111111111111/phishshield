(function (root) {
  const SUSPICIOUS_WORDS = [
    "verify",
    "urgent",
    "kyc",
    "otp",
    "reward",
    "claim",
    "prize",
    "blocked",
    "password",
    "payment",
    "parcel",
    "click here",
    "limited time",
  ];
  const SHORTENERS = new Set([
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "cutt.ly",
    "shorturl.at",
  ]);
  const BRANDS = [
    "amazon",
    "google",
    "microsoft",
    "paypal",
    "netflix",
    "apple",
    "instagram",
    "facebook",
    "whatsapp",
    "sbi",
    "hdfc",
    "icici",
  ];

  function isIpv4(hostname) {
    const parts = hostname.split(".");
    if (parts.length !== 4) return false;
    return parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
  }

  function isIpAddress(hostname) {
    if (!hostname) return false;
    if (isIpv4(hostname)) return true;
    return hostname.includes(":");
  }

  function urlReasons(url) {
    const findings = [];
    const candidate = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(url) ? url : `https://${url}`;
    let parsed;
    try {
      parsed = new URL(candidate);
    } catch {
      return findings;
    }

    const host = (parsed.hostname || "").toLowerCase().replace(/^\[|\]$/g, "");
    const fullUrl = candidate.toLowerCase();

    if (parsed.protocol !== "https:") {
      findings.push([15, "The link does not use HTTPS, so its connection may not be protected."]);
    }
    if (host && isIpAddress(host)) {
      findings.push([30, "The link uses a raw IP address instead of a normal website name."]);
    }
    if (SHORTENERS.has(host)) {
      findings.push([20, "This is a shortened link, which can hide its real destination."]);
    }
    if (candidate.length > 100) {
      findings.push([10, "The link is unusually long, which can be used to hide a misleading destination."]);
    }
    if (candidate.includes("%") || candidate.includes("@")) {
      findings.push([15, "The link contains encoded characters or an @ symbol that can obscure the true destination."]);
    }
    if ((host.match(/\./g) || []).length >= 3) {
      findings.push([10, "The link has many subdomains, a pattern often used to imitate trusted sites."]);
    }
    if ((host.match(/-/g) || []).length >= 2) {
      findings.push([8, "The domain has multiple hyphens, which is common in imitation domains."]);
    }
    for (const brand of BRANDS) {
      if (host.includes(brand) && !(host === `${brand}.com` || host.endsWith(`.${brand}.com`))) {
        findings.push([25, `The domain mentions '${brand}' but does not look like its official domain.`]);
        break;
      }
    }
    const wordHits = SUSPICIOUS_WORDS.filter((word) => fullUrl.includes(word)).sort();
    if (wordHits.length > 0) {
      findings.push([
        Math.min(20, 5 * wordHits.length),
        `The link contains pressure-related terms: ${wordHits.slice(0, 4).join(", ")}.`,
      ]);
    }
    return findings;
  }

  function messageReasons(message) {
    const lowered = message.toLowerCase();
    const findings = [];
    const hits = SUSPICIOUS_WORDS.filter((word) => lowered.includes(word)).sort();
    if (hits.length > 0) {
      findings.push([
        Math.min(35, 6 * hits.length),
        `The message uses scam-associated language: ${hits.slice(0, 5).join(", ")}.`,
      ]);
    }
    if (/\b(otp|cvv|pin|password)\b/.test(lowered)) {
      findings.push([30, "The message asks for sensitive authentication or payment information."]);
    }
    if (/\b(today|immediately|within \d+ hours?|last chance)\b/.test(lowered)) {
      findings.push([15, "The message creates urgency, a common social-engineering tactic."]);
    }
    const urls = message.match(/(?:https?:\/\/|www\.)[^\s]+/gi) || [];
    for (const url of urls) {
      findings.push(...urlReasons(url));
    }
    return findings;
  }

  function scanText(content) {
    const trimmed = String(content || "").trim();
    const looksLikeUrl = /^(?:https?:\/\/)?[^\s/]+(?:\/[^\s]*)?$/.test(trimmed) && !trimmed.includes(" ");
    const findings = looksLikeUrl ? urlReasons(trimmed) : messageReasons(trimmed);
    const score = Math.min(
      100,
      findings.reduce((acc, [weight]) => acc + weight, 0),
    );
    let level = "Low Risk";
    if (score >= 60) level = "Dangerous";
    else if (score >= 25) level = "Suspicious";
    const reasons =
      findings.length > 0
        ? findings.map(([, reason]) => reason)
        : ["No common phishing indicators were found in the text, though the destination itself is unverified and not guaranteed to be safe."];
    return {
      risk_score: score,
      risk_level: level,
      content_type: looksLikeUrl ? "url" : "message",
      reasons,
    };
  }

  function checkLinkTextMismatch(anchorText, href) {
    const text = String(anchorText || "").trim();
    if (!text || !href) return { mismatch: false };
    const domainMatch = text.match(/\b([a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|in|org|net|co\.in|gov\.in|bank\.in))\b/i);
    if (!domainMatch) return { mismatch: false };
    const visibleDomain = domainMatch[1].toLowerCase();
    let targetHost = "";
    try {
      targetHost = new URL(href).hostname.toLowerCase().replace(/^www\./, "");
    } catch {
      return { mismatch: false };
    }
    const cleanVisible = visibleDomain.replace(/^www\./, "");
    if (!targetHost || targetHost === cleanVisible || targetHost.endsWith(`.${cleanVisible}`)) {
      return { mismatch: false };
    }
    return { mismatch: true, visibleDomain: cleanVisible, targetHost };
  }

  const api = { scanText, checkLinkTextMismatch };
  root.PhishShieldScanner = api;
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
})(typeof globalThis !== "undefined" ? globalThis : self);

import React, { useMemo, useState } from "react";
import { DEFAULT_API_URL, submitScan } from "./api.js";
import "./PhishShield.css";

const API_URL = import.meta.env.VITE_API_URL || DEFAULT_API_URL;

const DEMOS = [
  { label: "Low-risk URL", kind: "mint", value: "https://www.example.com" },
  { label: "KYC + OTP scam", kind: "amber", value: "Your KYC will expire today. Verify now at http://198.51.100.42/login and share your OTP." },
  { label: "Brand look-alike", kind: "coral", value: "https://paypal-verify.example/account/login" },
  { label: "Shortened link", kind: "violet", value: "http://bit.ly/verify-prize-now" },
];

const MOCKS = {
  low: {
    scan_reference: "261127000101", risk_score: 12, risk_level: "Low Risk",
    content_type: "url", reasons: ["No obvious urgency or credential request detected.", "The domain uses a familiar example-domain pattern."],
    explanation: "We did not find strong warning signs in this text. That does not prove the destination is safe—this link is still unverified. Only visit it if you expected it and trust the sender.",
    ml_probability: 0.08, campaign_detected: false,
  },
  suspicious: {
    scan_reference: "261127000102", risk_score: 46, risk_level: "Suspicious",
    content_type: "url", reasons: ["The domain contains a brand-like name with an unusual extra word.", "The URL includes a sign-in path that may be used to collect credentials."],
    explanation: "This link has a few warning signs. The address resembles a familiar service, but the domain is not that service's official domain. Do not enter a password or payment details.",
    ml_probability: 0.71, campaign_detected: false,
  },
  dangerous: {
    scan_reference: "261127000103", risk_score: 94, risk_level: "Dangerous",
    content_type: "message", reasons: ["Creates urgency with a KYC-expiry threat.", "Requests an OTP, which should never be shared with another person.", "Uses a raw IP address instead of a recognizable organization domain."],
    explanation: "This message is very likely to be a scam. It pressures you to act quickly and asks for your OTP. Do not reply, share a code, or use the link. Contact the organization using its official app or a number you already trust.",
    ml_probability: 0.98, campaign_detected: true,
  },
};

function Icon({ name, size = 18 }) {
  const common = { width: size, height: size, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: 1.8, strokeLinecap: "round", strokeLinejoin: "round", "aria-hidden": true };
  const paths = {
    shield: <><path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11Z"/><path d="m9 12 2 2 4-4"/></>,
    lock: <><rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 1 1 8 0v3"/></>,
    copy: <><rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3"/></>,
    arrow: <><path d="M5 12h14"/><path d="m13 6 6 6-6 6"/></>,
    spark: <><path d="m12 3 1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8L12 3Z"/><path d="m19 16 .8 2.2L22 19l-2.2.8L19 22l-.8-2.2L16 19l2.2-.8L19 16Z"/></>,
    clock: <><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></>,
    alert: <><path d="M12 3 2.8 20h18.4L12 3Z"/><path d="M12 9v4m0 3h.01"/></>,
    close: <><path d="m18 6-12 12M6 6l12 12"/></>,
  };
  return <svg {...common}>{paths[name] || paths.shield}</svg>;
}

function getTier(score) {
  if (score <= 24) return { key: "low", label: "Low Risk (Unverified)", tone: "low" };
  if (score <= 59) return { key: "suspicious", label: "Suspicious", tone: "suspicious" };
  return { key: "dangerous", label: "Dangerous", tone: "dangerous" };
}

function normalizeResult(data) {
  const score = Math.max(0, Math.min(100, Number(data?.risk_score) || 0));
  return {
    ...data,
    risk_score: score,
    reasons: Array.isArray(data?.reasons) ? data.reasons : [],
    explanation: data?.explanation || "No plain-language explanation was provided.",
    scan_reference: String(data?.scan_reference || "Unavailable"),
    content_type: data?.content_type || "message",
  };
}

function RiskGauge({ score, tier }) {
  const radius = 64;
  const circumference = 2 * Math.PI * radius;
  const progress = circumference * (score / 100);
  return (
    <div className={`risk-gauge ${tier.tone}`} role="img" aria-label={`Risk score ${score} out of 100`}>
      <svg viewBox="0 0 160 160" className="gauge-svg">
        <circle className="gauge-track" cx="80" cy="80" r={radius} />
        <circle className="gauge-progress" cx="80" cy="80" r={radius}
          strokeDasharray={`${progress} ${circumference}`} />
      </svg>
      <div className="gauge-center">
        <strong>{score}<small>/100</small></strong>
        <span>risk score</span>
      </div>
    </div>
  );
}

export default function PhishShield() {
  const [content, setContent] = useState("");
  const [language, setLanguage] = useState("en");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [recent, setRecent] = useState([]);
  const [preview, setPreview] = useState("dangerous");
  const [copied, setCopied] = useState(false);

  const activeResult = result || (preview === "rate" ? null : MOCKS[preview]);
  const tier = useMemo(() => activeResult ? getTier(activeResult.risk_score) : null, [activeResult]);
  const isPreview = !result && preview !== "rate";

  function useDemo(demo) {
    setContent(demo.value);
    setError(null);
  }

  function showPreview(value) {
    setPreview(value);
    setResult(null);
    setError(value === "rate" ? { type: "rate", message: "We’ve reached the scan limit for now. Please wait a moment and try again." } : null);
  }

  async function handleScan(event) {
    event?.preventDefault();
    if (content.trim().length < 3 || loading) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      // Submitted text is sent only to the configured analysis API. This app never
      // opens, fetches, previews, or executes a URL found in the submitted content.
      // api.js owns the POST /api/scan request and returns the parsed response.
      const data = normalizeResult(await submitScan({ content: content.trim(), language, apiUrl: API_URL }));
      setResult(data);
      setPreview("");
      setRecent((items) => [data, ...items.filter((item) => item.scan_reference !== data.scan_reference)].slice(0, 4));
    } catch (err) {
      if (err?.status === 429) {
        setError({ type: "rate", message: err.message || "Too many scan requests. Please wait a moment and try again." });
      } else {
        setError({
          type: "offline",
          message: err?.message || "We can’t reach the PhishShield checker right now. Check that the local API is running, then try again. Your text has not been checked.",
        });
      }
    } finally {
      setLoading(false);
    }
  }

  async function copyReference() {
    if (!activeResult?.scan_reference) return;
    try {
      await navigator.clipboard.writeText(activeResult.scan_reference);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      setError({ type: "offline", message: "Copy wasn’t available in this browser. You can select the reference and copy it manually." });
    }
  }

  function selectRecent(item) {
    setResult(item);
    setPreview("");
    setError(null);
  }

  const isHindi = language === "hi";

  return (
    <main className="ps-app">
      <header className="topbar">
        <a className="brand" href="#top" aria-label="PhishShield home">
          <span className="brand-mark"><Icon name="shield" size={22} /></span>
          <span>phish<span>shield</span><small>CHECK BEFORE YOU CLICK.</small></span>
        </a>
        <div className="topbar-right"><span className="privacy-mini"><i /> Private by design</span><span className="topbar-divider" />
          <label className="sr-only" htmlFor="language">Explanation language</label>
          <select id="language" className="language-select" value={language} onChange={(e) => setLanguage(e.target.value)}>
            <option value="en">English</option><option value="hi">हिन्दी</option>
          </select>
        </div>
      </header>

      <section className="hero" id="top">
        <div className="hero-copy">
          <div className="eyebrow"><span className="eyebrow-dot" /> A calmer way to check suspicious messages</div>
          <h1>{isHindi ? <>क्लिक करने से पहले,<br /><em>जाँच लें।</em></> : <>A second look<br /><em>before you click.</em></>}</h1>
          <p>{isHindi ? "संदिग्ध लिंक या संदेश का टेक्स्ट यहाँ पेस्ट करें। हम लिंक खोले बिना उसकी जाँच करते हैं।" : "Paste a suspicious link or message. We’ll look for warning signs without ever opening the link."}</p>
          <div className="trust-strip">
            <div><span className="trust-icon"><Icon name="lock" size={16} /></span><span><b>Zero-click</b><small>Text analysis</small></span></div>
            <div><span className="trust-icon"><span className="lang-glyph">अ</span></span><span><b>English & हिन्दी</b><small>Clear explanations</small></span></div>
            <div><span className="trust-icon"><Icon name="shield" size={16} /></span><span><b>No raw IPs stored</b><small>Salted privacy logs</small></span></div>
          </div>
        </div>
        <div className="hero-art" aria-hidden="true">
          <div className="orbit orbit-one" /><div className="orbit orbit-two" />
          <div className="art-glow" /><div className="shield-illustration"><Icon name="shield" size={86} /><span className="shield-check">✓</span></div>
          <div className="float-card float-top"><span className="float-dot mint" /> Text only. No link visits.</div>
          <div className="float-card float-bottom"><span className="mini-bars"><i /><i /><i /></span> Signals, made simple</div>
        </div>
      </section>

      <section className="story-section" aria-labelledby="why-title">
        <div className="story-intro">
          <span className="step-label">THE PROBLEM WE’RE SOLVING</span>
          <h2 id="why-title">Scams are getting more convincing.<br /><em>Knowing what to trust shouldn’t be hard.</em></h2>
          <p>One urgent text can make anyone pause: a KYC warning, a parcel delay, a too-good-to-be-true job offer. PhishShield helps turn that moment of uncertainty into a clearer next step.</p>
        </div>
        <div className="threat-grid">
          <article className="threat-card"><span className="threat-symbol amber-symbol">!</span><div><b>Fake KYC &amp; bank alerts</b><p>Messages that pressure you to “verify now” or share an OTP.</p></div></article>
          <article className="threat-card"><span className="threat-symbol coral-symbol">↗</span><div><b>Impersonation links</b><p>Look-alike websites designed to resemble familiar brands.</p></div></article>
          <article className="threat-card"><span className="threat-symbol violet-symbol">%</span><div><b>Prize, parcel &amp; job scams</b><p>Unexpected rewards, delivery fees, and suspicious offers.</p></div></article>
        </div>
      </section>

      <section className="how-section" aria-labelledby="how-title">
        <div className="section-title-block">
          <span className="step-label">SIMPLE BY DESIGN</span>
          <h2 id="how-title">A safer pause in four steps.</h2>
          <p>No technical knowledge needed. Just paste the text and understand the signals.</p>
        </div>
        <div className="steps-grid">
          <article className="how-step"><span className="step-number">01</span><span className="how-icon"><svg viewBox="0 0 24 24"><path d="M8 5h8M8 9h8M8 13h5M6 3h12a2 2 0 0 1 2 2v14H4V5a2 2 0 0 1 2-2Z"/></svg></span><b>Paste</b><p>Copy in a suspicious link, SMS, or chat message.</p></article>
          <article className="how-step"><span className="step-number">02</span><span className="how-icon"><svg viewBox="0 0 24 24"><circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 5 5M8 10h5M10.5 7.5v5"/></svg></span><b>Analyze</b><p>PhishShield checks the submitted text for warning signs.</p></article>
          <article className="how-step"><span className="step-number">03</span><span className="how-icon"><svg viewBox="0 0 24 24"><path d="M12 3 3 7v5c0 5 4 8 9 9 5-1 9-4 9-9V7l-9-4Z"/><path d="m8 12 2.5 2.5L16 9"/></svg></span><b>Understand</b><p>Get a clear risk level and plain-language explanation.</p></article>
          <article className="how-step"><span className="step-number">04</span><span className="how-icon"><svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11Z"/><path d="M9 12h6"/></svg></span><b>Choose carefully</b><p>Use the evidence to decide your next step—without rushing.</p></article>
        </div>
      </section>

      <section className="risk-guide" aria-labelledby="risk-guide-title">
        <div className="risk-guide-copy">
          <span className="step-label">READ THE RESULT</span>
          <h2 id="risk-guide-title">Three levels. One clearer decision.</h2>
          <p>Risk scores are guidance based on signals found in the submitted text—not a guarantee about what will happen if you visit a link.</p>
        </div>
        <div className="risk-guide-cards">
          <article className="guide-tier low-tier"><span className="guide-range">00—24</span><b>Low Risk (Unverified)</b><p>No strong warning signs found. The link is still unverified, not guaranteed safe.</p></article>
          <article className="guide-tier suspicious-tier"><span className="guide-range">25—59</span><b>Suspicious</b><p>Some signals deserve caution. Pause and verify through an official channel.</p></article>
          <article className="guide-tier dangerous-tier"><span className="guide-range">60—100</span><b>Dangerous</b><p>Strong scam indicators detected. Do not share details or engage with the message.</p></article>
        </div>
      </section>

      <section className="privacy-section" aria-labelledby="privacy-title">
        <div className="privacy-emblem"><svg viewBox="0 0 80 90" aria-hidden="true"><path d="M40 4 70 16v22c0 21-13 34-30 44C23 72 10 59 10 38V16L40 4Z"/><path d="m27 42 9 9 18-20"/></svg></div>
        <div className="privacy-copy">
          <span className="step-label">BUILT AROUND TRUST</span>
          <h2 id="privacy-title">Your caution deserves privacy.</h2>
          <p>PhishShield analyzes what you paste as text. It does not open, fetch, preview, or execute submitted links. The goal is to help people understand suspicious messages without putting them at greater risk.</p>
          <div className="privacy-points"><span>✓ Zero-click text analysis</span><span>✓ English &amp; हिन्दी explanations</span><span>✓ No raw IPs stored in privacy logs</span></div>
        </div>
      </section>

      <section className="faq-section" aria-labelledby="faq-title">
        <div className="section-title-block"><span className="step-label">GOOD TO KNOW</span><h2 id="faq-title">A few things you might be wondering.</h2></div>
        <div className="faq-grid">
          <article><b>Does PhishShield open the link?</b><p>No. Submitted URLs are treated as text only. The checker looks at the text and never visits the destination.</p></article>
          <article><b>Does “Low Risk” mean safe?</b><p>No. It means no strong warning signs were identified. Unknown links remain unverified, so use your judgement.</p></article>
          <article><b>Can it check messages as well as URLs?</b><p>Yes. You can paste SMS, WhatsApp alerts, KYC notices, parcel updates, job offers, and other suspicious text.</p></article>
          <article><b>Who is PhishShield for?</b><p>It is designed to make scam-warning signals easier to understand for students, parents, and families.</p></article>
        </div>
      </section>

      <section className="workspace" id="checker">
        <div className="input-column">
          <div className="section-heading"><div><span className="step-label">YOUR CHECK</span><h2>What looks suspicious?</h2></div><span className="input-count">{content.length.toLocaleString()} <i>/ 5,000</i></span></div>
          <form className="input-card" onSubmit={handleScan}>
            <label htmlFor="scan-content" className="sr-only">Paste a link or suspicious message</label>
            <textarea id="scan-content" minLength={3} maxLength={5000} value={content} onChange={(e) => setContent(e.target.value)}
              placeholder="Paste a URL, SMS, WhatsApp message, KYC alert, parcel update, job offer…" />
            <div className="input-footer"><span><Icon name="lock" size={13} /> Your text is analyzed as text only</span>
              <button type="button" className="clear-button" onClick={() => { setContent(""); setError(null); }}> <Icon name="close" size={14} /> Clear</button>
            </div>
            <div className="form-actions">
              <button className="scan-button" type="submit" disabled={content.trim().length < 3 || loading}>
                {loading ? <><span className="spinner" /> Checking text…</> : <>Check safely <Icon name="arrow" size={17} /></>}
              </button>
              <span className="no-click-note"> <Icon name="shield" size={14} /> We never visit submitted links</span>
            </div>
          </form>
          <div className="demo-area"><div className="demo-title">TRY A SAFE EXAMPLE <span>·</span> Prefills only, never opens</div>
            <div className="demo-chips">{DEMOS.map((demo) => <button type="button" key={demo.label} className={`demo-chip ${demo.kind}`} onClick={() => useDemo(demo)}>{demo.label}<span>↗</span></button>)}</div>
          </div>
          <div className="safety-note"><Icon name="alert" size={17} /><p><b>Remember:</b> “Low Risk” means no strong warning signs were found. It is <u>not</u> a guarantee that a link is safe.</p></div>
        </div>

        <div className="result-column">
          <div className="result-heading"><div><span className="step-label">YOUR RESULT</span><h2>Clarity, not jargon.</h2></div>
            <span className="live-indicator"><i /> {result ? "LIVE CHECK" : "SAMPLE PREVIEW"}</span>
          </div>

          {error && <div className={`alert-banner ${error.type}`} role="alert"><span className="alert-symbol"><Icon name="alert" size={18} /></span><div><b>{error.type === "rate" ? "A little pause" : "Checker unavailable"}</b><p>{error.message}</p></div><button type="button" onClick={() => setError(null)} aria-label="Dismiss alert"><Icon name="close" size={16} /></button></div>}

          {activeResult && tier ? (
            <article className={`result-card ${tier.tone}`}>
              <div className="result-topline"><span className="result-kicker"><Icon name="spark" size={14} /> RISK OVERVIEW</span><span className="type-pill">{activeResult.content_type?.toLowerCase() === "url" ? "URL" : "MESSAGE"}</span></div>
              <div className="verdict-row"><RiskGauge score={activeResult.risk_score} tier={tier} /><div className="verdict-copy">
                <span className={`verdict-badge ${tier.tone}`}><i /> {tier.label}</span>
                <h3>{tier.tone === "low" ? "No strong red flags found." : tier.tone === "suspicious" ? "Take a closer look." : "Do not engage with this."}</h3>
                <p>{tier.tone === "low" ? "Still unverified. Stay alert." : tier.tone === "suspicious" ? "Some details deserve caution." : "This has multiple high-risk signals."}</p>
              </div></div>
              <div className="explanation-card"><div className="explanation-icon"><Icon name="shield" size={18} /></div><div><span>IN PLAIN LANGUAGE</span><p>{activeResult.explanation}</p></div></div>
              {activeResult.campaign_detected === true && <div className="campaign-pill"><span>↗</span> Repeated scam/campaign pattern detected</div>}
              <div className="evidence-section"><div className="subsection-heading"><h4>What we noticed</h4><span>{activeResult.reasons.length} indicators</span></div>
                {activeResult.reasons.length ? <ul className="evidence-list">{activeResult.reasons.map((reason, index) => <li key={`${index}-${reason}`}><span className="evidence-check"><Icon name="alert" size={13} /></span>{reason}</li>)}</ul> : <p className="empty-evidence">No specific indicators were returned for this check.</p>}
              </div>
              {activeResult.ml_probability !== null && activeResult.ml_probability !== undefined && <div className="ml-signal"><div className="ml-label"><span>ML confidence signal</span><b>{(Number(activeResult.ml_probability) * 100).toFixed(1)}%</b></div><div className="ml-track"><span style={{ width: `${Math.max(0, Math.min(100, Number(activeResult.ml_probability) * 100))}%` }} /></div><small>Phishing similarity — supporting evidence only, not a verdict by itself.</small></div>}
              <div className="reference-row"><div><span>SCAN REFERENCE</span><strong>{activeResult.scan_reference}</strong></div><button type="button" onClick={copyReference} className="copy-button"><Icon name="copy" size={14} /> {copied ? "Copied" : "Copy ref"}</button></div>
              {isPreview && <div className="preview-caption">Illustrative sample result · Not an actual scan</div>}
            </article>
          ) : !error ? <div className="empty-result"><div className="empty-orbit"><Icon name="shield" size={35} /></div><h3>Your result will appear here.</h3><p>Paste a message or link on the left, then choose <b>Check safely</b>. No link is opened.</p><div className="empty-foot"><Icon name="lock" size={14} /> Your check stays in this tab</div></div> : null}

          <div className="preview-switcher"><span>PREVIEW A RESULT</span><div className="preview-options">
            <button className={preview === "low" && !result ? "selected" : ""} onClick={() => showPreview("low")} type="button">Low risk</button>
            <button className={preview === "suspicious" && !result ? "selected" : ""} onClick={() => showPreview("suspicious")} type="button">Suspicious</button>
            <button className={preview === "dangerous" && !result ? "selected" : ""} onClick={() => showPreview("dangerous")} type="button">Dangerous</button>
            <button className={preview === "rate" ? "selected" : ""} onClick={() => showPreview("rate")} type="button">429 limit</button>
          </div></div>
          <div className="recent-card"><div className="recent-heading"><div><Icon name="clock" size={16} /><b>Recent checks</b></div><span>THIS TAB ONLY · LAST 4</span></div>
            {recent.length ? <ul>{recent.map((item) => { const itemTier = getTier(item.risk_score); return <li key={item.scan_reference}><button type="button" onClick={() => selectRecent(item)}><span className={`recent-dot ${itemTier.tone}`} /><span className="recent-type">{item.content_type === "url" ? "URL" : "MESSAGE"}</span><span className="recent-ref">{item.scan_reference}</span><span className={`recent-score ${itemTier.tone}`}>{item.risk_score}/100</span><Icon name="arrow" size={14} /></button></li>; })}</ul> : <p className="recent-empty">Your completed checks will show up here. They’re kept only in this tab.</p>}
          </div>
        </div>
      </section>

      <footer className="footer"><div className="footer-brand"><Icon name="shield" size={17} /> PhishShield</div><span>Helping students, parents &amp; families pause before they trust.</span><span className="footer-tag">CHECK BEFORE YOU CLICK.</span></footer>
    </main>
  );
}

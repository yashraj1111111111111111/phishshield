import React, { useState } from "react";
import { createRoot } from "react-dom/client";
import { DEFAULT_API_URL, submitScan } from "./api.js";
import "./styles.css";

const API_URL = import.meta.env.VITE_API_URL || DEFAULT_API_URL;

const SAMPLES = [
  { label: "Low-Risk URL", value: "https://www.example.com" },
  {
    label: "KYC + OTP Scam",
    value: "Your KYC will expire today. Verify now at http://198.51.100.42/login and share your OTP.",
  },
  { label: "Brand Look-alike", value: "https://paypal-verify.example/account/login" },
  { label: "Shortened Link", value: "http://bit.ly/verify-prize-now" },
];

function formatVerdict(level) {
  return level === "Low Risk" ? "Low Risk (Unverified)" : level;
}

function levelClass(level) {
  return String(level || "Low Risk").toLowerCase().replace(/\s+/g, "-");
}

function App() {
  const [content, setContent] = useState("");
  const [language, setLanguage] = useState("en");
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);
  const [loading, setLoading] = useState(false);

  async function handleScan(event) {
    event.preventDefault();
    setError("");
    setResult(null);
    setCopied(false);
    setLoading(true);
    try {
      const data = await submitScan({ content, language, apiUrl: API_URL });
      setResult(data);
      setHistory((prev) => [{ input: content.trim(), data }, ...prev].slice(0, 4));
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  function handleClear() {
    setContent("");
    setResult(null);
    setError("");
    setCopied(false);
  }

  async function handleCopyReference() {
    if (!result?.scan_reference || !navigator.clipboard) return;
    try {
      await navigator.clipboard.writeText(result.scan_reference);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  return (
    <main>
      <section className="hero">
        <div className="brand-row">
          <span className="brand-badge" aria-hidden="true">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.3" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <path d="m9 12 2 2 4-4" />
            </svg>
          </span>
          <p className="eyebrow">PHISHSHIELD • PRIVACY-FIRST SCAM GUARD</p>
        </div>
        <h1>Check before you click.</h1>
        <p className="subtitle">
          Paste a suspicious link or message. PhishShield inspects the text locally—it never opens, fetches, or executes submitted URLs.
        </p>
        <div className="trust-strip">
          <span className="trust-pill">Zero-Click Text Analysis</span>
          <span className="trust-pill">English &amp; हिन्दी Explanations</span>
          <span className="trust-pill">No Raw IPs Stored</span>
        </div>
      </section>

      <section className="panel">
        <div className="samples-row">
          <span className="samples-label">Try a safe demo input:</span>
          {SAMPLES.map((sample) => (
            <button
              key={sample.label}
              type="button"
              className="chip-btn"
              onClick={() => {
                setContent(sample.value);
                setError("");
              }}
            >
              {sample.label}
            </button>
          ))}
        </div>

        <form onSubmit={handleScan}>
          <div className="input-head">
            <label htmlFor="content">Suspicious URL or message</label>
            <span className="char-count">{content.length} / 5000</span>
          </div>
          <textarea
            id="content"
            value={content}
            onChange={(event) => setContent(event.target.value)}
            placeholder="Paste a link, KYC alert, parcel SMS, job offer, or prize message…"
            required
            minLength="3"
            maxLength="5000"
          />
          <div className="actions">
            <div className="actions-left">
              <select
                value={language}
                onChange={(event) => setLanguage(event.target.value)}
                aria-label="Explanation language"
              >
                <option value="en">English</option>
                <option value="hi">Hindi (हिन्दी)</option>
              </select>
              {content && (
                <button type="button" className="ghost-btn" onClick={handleClear}>
                  Clear
                </button>
              )}
            </div>
            <div className="actions-right">
              <button className="primary-btn" disabled={loading}>
                {loading ? "Analyzing safely…" : "Check safely"}
              </button>
            </div>
          </div>
        </form>

        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}

        {result && (
          <article className={`result ${levelClass(result.risk_level)}`}>
            <div className="score-card">
              <span className="score-label">{formatVerdict(result.risk_level)}</span>
              <strong className="score-value">
                {result.risk_score}
                <small>/100</small>
              </strong>
              <div className="meter-track" aria-hidden="true">
                <div className="meter-fill" style={{ width: `${Math.max(4, result.risk_score)}%` }} />
              </div>
              <p className="content-kind">Detected: {result.content_type}</p>
            </div>

            <div className="details">
              <div className="ref-row">
                <p className="reference">SCAN REF: {result.scan_reference}</p>
                <button type="button" className="copy-btn" onClick={handleCopyReference}>
                  {copied ? "Copied" : "Copy ref"}
                </button>
              </div>
              {result.campaign_detected && (
                <p className="campaign-tag">Repeated scam/campaign pattern detected</p>
              )}
              <p className="explanation">{result.explanation}</p>
              <h2>Evidence &amp; indicators</h2>
              <ul>
                {result.reasons.map((reason) => (
                  <li key={reason}>{reason}</li>
                ))}
              </ul>
              {result.ml_probability !== null && result.ml_probability !== undefined && (
                <p className="ml-signal">
                  ML confidence signal: {(result.ml_probability * 100).toFixed(1)}% phishing similarity (supporting evidence only)
                </p>
              )}
            </div>
          </article>
        )}

        {history.length > 0 && (
          <div className="history">
            <h2>Recent checks in this tab</h2>
            <div className="history-list">
              {history.map((item) => (
                <button
                  key={item.data.scan_reference}
                  type="button"
                  className="history-item"
                  onClick={() => {
                    setContent(item.input);
                    setResult(item.data);
                    setError("");
                  }}
                >
                  <span className="history-text">{item.input}</span>
                  <span className={`history-badge ${levelClass(item.data.risk_level)}`}>
                    {item.data.risk_level} ({item.data.risk_score})
                  </span>
                </button>
              ))}
            </div>
          </div>
        )}
      </section>

      <footer>
        PhishShield analyzes text only. A low risk score means no common text indicators were found—it is not a guarantee that an unverified site is safe.
      </footer>
    </main>
  );
}

createRoot(document.getElementById("root")).render(<App />);

import React, { useState } from "react";
import { createRoot } from "react-dom/client";
import { DEFAULT_API_URL, submitScan } from "./api.js";
import "./styles.css";

const API_URL = import.meta.env.VITE_API_URL || DEFAULT_API_URL;

function App() {
  const [content, setContent] = useState("");
  const [language, setLanguage] = useState("en");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleScan(event) {
    event.preventDefault();
    setError(""); setResult(null); setLoading(true);
    try {
      const data = await submitScan({ content, language, apiUrl: API_URL });
      setResult(data);
    } catch (err) {
      setError(err.message);
    } finally { setLoading(false); }
  }

  return <main>
    <section className="hero">
      <p className="eyebrow">PRIVACY-FIRST SCAM DETECTION</p>
      <h1>Check before you click.</h1>
      <p className="subtitle">Paste a suspicious link or message. PhishShield analyzes the text—it never opens the link.</p>
    </section>
    <section className="panel">
      <form onSubmit={handleScan}>
        <label htmlFor="content">Suspicious URL or message</label>
        <textarea id="content" value={content} onChange={(event) => setContent(event.target.value)} placeholder="Paste a link, KYC message, job offer, or prize alert…" required minLength="3" />
        <div className="actions">
          <select value={language} onChange={(event) => setLanguage(event.target.value)} aria-label="Explanation language">
            <option value="en">English</option><option value="hi">Hindi</option>
          </select>
          <button disabled={loading}>{loading ? "Checking…" : "Check safely"}</button>
        </div>
      </form>
      {error && <p className="error" role="alert">{error}</p>}
      {result && <article className={`result ${result.risk_level.toLowerCase().replace(/\s+/g, "-")}`}>
        <div className="score"><span>{result.risk_level === "Low Risk" ? "Low Risk (Unverified)" : result.risk_level}</span><strong>{result.risk_score}<small>/100</small></strong></div>
        <div className="details">
          <p className="reference">SCAN REF: {result.scan_reference}</p>
          {result.campaign_detected && <p className="campaign-tag">Repeated scam/campaign pattern detected</p>}
          <h2>Why this was flagged</h2>
          <ul>{result.reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul>
          {result.ml_probability !== null && result.ml_probability !== undefined && (
            <p className="ml-signal">ML confidence signal: {(result.ml_probability * 100).toFixed(1)}% phishing similarity (supporting evidence only)</p>
          )}
          <p className="explanation">{result.explanation}</p>
        </div>
      </article>}
    </section>
    <footer>PhishShield analyzes text only. A low score is not a guarantee of safety.</footer>
  </main>;
}

createRoot(document.getElementById("root")).render(<App />);

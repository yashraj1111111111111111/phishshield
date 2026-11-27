import React, { useState } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

const API_URL = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";

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
      const response = await fetch(`${API_URL}/api/scan`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ content, language })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Unable to scan this content.");
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
      {error && <p className="error">{error}</p>}
      {result && <article className={`result ${result.risk_level.toLowerCase()}`}>
        <div className="score"><span>{result.risk_level}</span><strong>{result.risk_score}<small>/100</small></strong></div>
        <div className="details"><p className="reference">SCAN REF: {result.scan_reference}</p><h2>Why this was flagged</h2><ul>{result.reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul><p className="explanation">{result.explanation}</p></div>
      </article>}
    </section>
    <footer>PhishShield analyzes text only. A low score is not a guarantee of safety.</footer>
  </main>;
}

createRoot(document.getElementById("root")).render(<App />);

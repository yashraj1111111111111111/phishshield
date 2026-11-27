"""Streamlit entrypoint for standalone and Streamlit Community Cloud deployment."""
from __future__ import annotations

import uuid

import streamlit as st
from fastapi import HTTPException

from app.database.connection import initialize_database
from app.services.scan_pipeline import run_scan_pipeline

st.set_page_config(page_title="PhishShield — Check Before You Click", page_icon="🛡️", layout="centered")

st.markdown(
    """
    <style>
      .ps-pill-row { display: flex; flex-wrap: wrap; gap: 8px; margin: 6px 0 18px; }
      .ps-pill {
        font-size: 0.78rem;
        padding: 4px 10px;
        border-radius: 999px;
        border: 1px solid rgba(112, 221, 189, 0.35);
        background: rgba(112, 221, 189, 0.08);
        color: #9be8d0;
      }
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_resource
def _init_db() -> bool:
    initialize_database()
    return True


_init_db()

if "client_id" not in st.session_state:
    st.session_state.client_id = f"st-{uuid.uuid4().hex[:12]}"
if "scan_input" not in st.session_state:
    st.session_state.scan_input = ""
if "scan_history" not in st.session_state:
    st.session_state.scan_history = []

st.caption("PHISHSHIELD • PRIVACY-FIRST SCAM GUARD")
st.title("Check before you click.")
st.write(
    "Paste a suspicious link or message. PhishShield inspects the text locally—it never opens, fetches, or executes submitted URLs."
)
st.markdown(
    '<div class="ps-pill-row">'
    '<span class="ps-pill">Zero-Click Text Analysis</span>'
    '<span class="ps-pill">English &amp; हिन्दी Explanations</span>'
    '<span class="ps-pill">Salted Privacy Logs</span>'
    "</div>",
    unsafe_allow_html=True,
)

sample_col1, sample_col2, sample_col3 = st.columns(3)
if sample_col1.button("Low-risk demo", use_container_width=True):
    st.session_state.scan_input = "https://www.example.com"
if sample_col2.button("KYC + OTP scam", use_container_width=True):
    st.session_state.scan_input = (
        "Your KYC will expire today. Verify now at http://198.51.100.42/login and share your OTP."
    )
if sample_col3.button("Brand look-alike", use_container_width=True):
    st.session_state.scan_input = "https://paypal-verify.example/account/login"

with st.form("scan_form"):
    content = st.text_area(
        "Suspicious URL or message",
        key="scan_input",
        height=145,
        max_chars=5000,
        placeholder="Paste a link, KYC alert, parcel SMS, job offer, or prize message…",
    )
    col_lang, col_btn = st.columns([1, 2])
    language_label = col_lang.selectbox("Explanation language", ["English", "Hindi"])
    submitted = col_btn.form_submit_button("Check safely", type="primary", use_container_width=True)

if submitted:
    trimmed = content.strip()
    if len(trimmed) < 3:
        st.error("Please enter at least 3 characters to scan.")
    else:
        language = "hi" if language_label == "Hindi" else "en"
        try:
            outcome = run_scan_pipeline(trimmed, language, st.session_state.client_id)
        except HTTPException as exc:
            st.error(str(exc.detail))
        else:
            st.session_state.scan_history = [
                {
                    "ref": outcome.scan_reference,
                    "level": outcome.risk_level,
                    "score": outcome.risk_score,
                    "preview": trimmed[:80],
                },
                *st.session_state.scan_history,
            ][:4]

            st.divider()
            st.caption(f"SCAN REF: {outcome.scan_reference} • DETECTED: {outcome.content_type.upper()}")
            metric_col, badge_col = st.columns([1, 2])
            metric_col.metric("Risk Score", f"{outcome.risk_score}/100")
            if outcome.risk_level == "Dangerous":
                badge_col.error(f"Verdict: **{outcome.risk_level}**")
            elif outcome.risk_level == "Suspicious":
                badge_col.warning(f"Verdict: **{outcome.risk_level}**")
            else:
                badge_col.success("Verdict: **Low Risk (Unverified)**")

            st.progress(max(0.02, min(1.0, outcome.risk_score / 100)))

            if outcome.campaign_detected:
                st.warning("Repeated scam/campaign pattern detected across recent scans.")

            st.info(outcome.explanation)

            st.subheader("Evidence & indicators")
            for reason in outcome.reasons:
                st.markdown(f"- {reason}")

            if outcome.ml_probability is not None:
                st.caption(
                    f"ML confidence signal: {outcome.ml_probability * 100:.1f}% phishing similarity (supporting evidence only)"
                )

if st.session_state.scan_history:
    with st.expander("Recent checks in this session"):
        for item in st.session_state.scan_history:
            st.markdown(f"- **{item['level']} ({item['score']}/100)** `{item['ref']}` — {item['preview']}")

st.caption(
    "PhishShield analyzes text only. A low risk score means no common text indicators were found—it is not a guarantee that an unverified site is safe."
)

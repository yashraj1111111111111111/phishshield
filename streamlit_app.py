"""Streamlit entrypoint for standalone and Streamlit Community Cloud deployment."""
from __future__ import annotations

import uuid

import streamlit as st
from fastapi import HTTPException

from app.database.connection import initialize_database
from app.services.scan_pipeline import run_scan_pipeline

st.set_page_config(page_title="PhishShield", page_icon="🛡️", layout="centered")


@st.cache_resource
def _init_db() -> bool:
    initialize_database()
    return True


_init_db()

if "client_id" not in st.session_state:
    st.session_state.client_id = f"st-{uuid.uuid4().hex[:12]}"
if "scan_input" not in st.session_state:
    st.session_state.scan_input = ""

st.caption("PRIVACY-FIRST SCAM DETECTION")
st.title("Check before you click.")
st.write("Paste a suspicious link or message. PhishShield analyzes the text—it never opens, fetches, or executes submitted links.")

sample_col1, sample_col2 = st.columns(2)
if sample_col1.button("Try safe example", use_container_width=True):
    st.session_state.scan_input = "https://www.example.com"
if sample_col2.button("Try scam demo", use_container_width=True):
    st.session_state.scan_input = "Your KYC will expire today. Verify now at http://198.51.100.42/login and share your OTP."

with st.form("scan_form"):
    content = st.text_area(
        "Suspicious URL or message",
        key="scan_input",
        height=150,
        max_chars=5000,
        placeholder="Paste a link, KYC message, job offer, or prize alert…",
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
            st.divider()
            st.caption(f"SCAN REF: {outcome.scan_reference}")
            metric_col, badge_col = st.columns([1, 2])
            metric_col.metric("Risk Score", f"{outcome.risk_score}/100")
            if outcome.risk_level == "Dangerous":
                badge_col.error(f"Verdict: **{outcome.risk_level}**")
            elif outcome.risk_level == "Suspicious":
                badge_col.warning(f"Verdict: **{outcome.risk_level}**")
            else:
                badge_col.success(f"Verdict: **{outcome.risk_level}**")

            if outcome.campaign_detected:
                st.warning("Repeated scam/campaign pattern detected across recent scans.")

            st.subheader("Why this was flagged")
            for reason in outcome.reasons:
                st.markdown(f"- {reason}")

            if outcome.ml_probability is not None:
                st.caption(
                    f"ML confidence signal: {outcome.ml_probability * 100:.1f}% phishing similarity (supporting evidence only)"
                )

            st.info(outcome.explanation)

st.caption("PhishShield analyzes text only. A low score is not a guarantee of safety.")

"""Streamlit entrypoint for standalone and Streamlit Community Cloud deployment."""
from __future__ import annotations

import html
import uuid

import streamlit as st
from fastapi import HTTPException

from app.database.connection import initialize_database
from app.services.scan_pipeline import ScanOutcome, run_scan_pipeline

st.set_page_config(page_title="PhishShield — Check Before You Click", page_icon="🛡️", layout="wide")

CUSTOM_CSS = """
<style>
  @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;700&family=Manrope:wght@600;700;800&display=swap');

  .stApp {
    background: radial-gradient(ellipse at 15% 5%, rgba(35, 91, 110, 0.22), transparent 36%), #07111f;
    color: #eaf2f8;
    font-family: 'DM Sans', ui-sans-serif, system-ui, sans-serif;
  }
  .block-container {
    max-width: 1180px;
    padding-top: 1.4rem;
    padding-bottom: 2.5rem;
  }
  h1, h2, h3, h4 {
    font-family: 'Manrope', ui-sans-serif, system-ui, sans-serif;
    color: #f3f7fa;
  }
  .ps-topbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding-bottom: 14px;
    border-bottom: 1px solid rgba(160, 190, 215, 0.14);
    margin-bottom: 18px;
  }
  .ps-brand {
    display: flex;
    align-items: center;
    gap: 11px;
    font: 800 20px/1 'Manrope', sans-serif;
    color: #f4f8fb;
  }
  .ps-brand-mark {
    width: 36px;
    height: 36px;
    border-radius: 11px;
    display: grid;
    place-items: center;
    background: rgba(112, 221, 189, 0.13);
    border: 1px solid rgba(112, 221, 189, 0.28);
    color: #70ddbd;
  }
  .ps-brand small {
    display: block;
    margin-top: 4px;
    color: #8297aa;
    font: 700 9px/1 'DM Sans', sans-serif;
    letter-spacing: 1.7px;
  }
  .ps-brand .accent { color: #70ddbd; }
  .ps-privacy-pill {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    font-size: 12px;
    color: #9bb0c1;
    padding: 6px 12px;
    border-radius: 999px;
    border: 1px solid rgba(160, 190, 215, 0.16);
    background: #0b1c31;
  }
  .ps-dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: #70ddbd;
    box-shadow: 0 0 10px #70ddbd77;
  }
  .ps-hero {
    display: grid;
    grid-template-columns: 1.25fr 0.75fr;
    gap: 28px;
    align-items: center;
    padding: 18px 0 26px;
  }
  .ps-eyebrow {
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 1.6px;
    color: #70ddbd;
    text-transform: uppercase;
    margin-bottom: 10px;
  }
  .ps-hero h1 {
    font-size: clamp(2.1rem, 4.2vw, 3.3rem);
    line-height: 1.1;
    letter-spacing: -0.04em;
    margin: 0 0 12px;
  }
  .ps-hero h1 em { font-style: normal; color: #70ddbd; }
  .ps-hero-sub {
    color: #9eb0c0;
    font-size: 15px;
    line-height: 1.65;
    max-width: 560px;
    margin-bottom: 18px;
  }
  .ps-trust-row {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
  }
  .ps-trust-chip {
    background: #0b1c31;
    border: 1px solid rgba(112, 221, 189, 0.22);
    border-radius: 10px;
    padding: 8px 12px;
    font-size: 12px;
    color: #dce8ef;
  }
  .ps-trust-chip span { display: block; font-size: 10px; color: #8297aa; margin-top: 2px; }
  .ps-hero-card {
    background: linear-gradient(145deg, #0e243b, #091829);
    border: 1px solid rgba(112, 221, 189, 0.24);
    border-radius: 16px;
    padding: 22px;
    text-align: center;
    box-shadow: 0 18px 46px rgba(2, 8, 20, 0.45);
  }
  .ps-hero-shield {
    width: 72px;
    height: 78px;
    margin: 0 auto 12px;
    display: grid;
    place-items: center;
    background: linear-gradient(145deg, #173b4b, #0c2638);
    border: 1px solid #70ddbd;
    clip-path: polygon(50% 0, 91% 16%, 88% 66%, 50% 100%, 12% 66%, 9% 16%);
    color: #70ddbd;
    font-size: 28px;
    font-weight: 800;
  }
  .ps-hero-card p { font-size: 12px; color: #b7cad8; margin: 4px 0 0; }
  .ps-section-divider {
    border-top: 1px solid rgba(160, 190, 215, 0.14);
    margin: 24px 0 20px;
    padding-top: 22px;
  }
  .ps-card-grid-3 {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 12px;
    margin-top: 14px;
  }
  .ps-card-grid-4 {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 12px;
    margin-top: 14px;
  }
  .ps-info-card {
    background: #0b1c31;
    border: 1px solid rgba(160, 190, 215, 0.14);
    border-radius: 12px;
    padding: 15px;
  }
  .ps-info-card b { display: block; font-size: 13px; color: #eaf2f8; margin-bottom: 6px; }
  .ps-info-card p { font-size: 12px; line-height: 1.55; color: #8da2b3; margin: 0; }
  .ps-tier-low { border-top: 3px solid #70ddbd; }
  .ps-tier-low .ps-tier-range { color: #70ddbd; }
  .ps-tier-sus { border-top: 3px solid #ffce77; }
  .ps-tier-sus .ps-tier-range { color: #ffce77; }
  .ps-tier-dan { border-top: 3px solid #ff8b89; }
  .ps-tier-dan .ps-tier-range { color: #ff8b89; }
  .ps-tier-range { font: 800 16px/1 'Manrope', sans-serif; margin-bottom: 8px; display: block; }

  .ps-gauge-wrap {
    display: flex;
    align-items: center;
    gap: 18px;
    background: linear-gradient(145deg, #0e2238, #0a1a2d);
    border: 1px solid rgba(144, 176, 199, 0.18);
    border-radius: 14px;
    padding: 16px;
    margin-bottom: 12px;
  }
  .ps-gauge {
    position: relative;
    width: 118px;
    height: 118px;
    flex: none;
  }
  .ps-gauge svg { width: 100%; height: 100%; transform: rotate(-90deg); }
  .ps-gauge-center {
    position: absolute;
    inset: 0;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    line-height: 1.1;
  }
  .ps-gauge-center strong { font: 800 26px 'Manrope', sans-serif; color: #f3f8fb; }
  .ps-gauge-center small { font-size: 11px; color: #8297aa; }
  .ps-gauge-center span { font-size: 10px; color: #8297aa; margin-top: 2px; }
  .ps-ref-pill {
    font-size: 11px;
    letter-spacing: 0.9px;
    color: #70ddbd;
    font-weight: 700;
  }
  .stButton > button[kind="primary"] {
    background: #70ddbd !important;
    color: #06211b !important;
    border: 0 !important;
    font-weight: 800 !important;
  }
  .stTextArea textarea {
    background-color: #0b1c31 !important;
    color: #eaf2f8 !important;
    border-color: rgba(144, 176, 199, 0.25) !important;
  }
  @media (max-width: 780px) {
    .ps-hero, .ps-card-grid-3, .ps-card-grid-4 { grid-template-columns: 1fr; }
  }
</style>
"""

COPY = {
    "en": {
        "tagline": "CHECK BEFORE YOU CLICK.",
        "private": "Private by design",
        "eyebrow": "A calmer way to check suspicious messages",
        "hero_top": "A second look",
        "hero_accent": "before you click.",
        "hero_sub": "Paste a suspicious link or message. We’ll look for warning signs without ever opening the link.",
        "trust": [
            ("Zero-click", "Text analysis only"),
            ("English & हिन्दी", "Clear explanations"),
            ("No raw IPs stored", "Salted privacy logs"),
        ],
        "hero_card_title": "Text only. No link visits.",
        "hero_card_sub": "Explainable rules + UCI-trained ML confidence signal + local Qwen explanations.",
        "your_check": "YOUR CHECK",
        "check_heading": "What looks suspicious?",
        "demo_caption": "Try a safe demo input (prefills text only, never opens links):",
        "demos": [
            ("Low-risk URL", "https://www.example.com"),
            ("KYC + OTP scam", "Your KYC will expire today. Verify now at http://198.51.100.42/login and share your OTP."),
            ("Brand look-alike", "https://paypal-verify.example/account/login"),
            ("Shortened link", "http://bit.ly/verify-prize-now"),
        ],
        "input_label": "Suspicious URL or message",
        "placeholder": "Paste a URL, SMS, WhatsApp message, KYC alert, parcel update, job offer…",
        "check_btn": "Check safely",
        "remember": "Remember: “Low Risk (Unverified)” means no strong text indicators were found—it is not a guarantee that an unverified site is safe.",
        "your_result": "YOUR RESULT",
        "result_heading": "Clarity, not jargon.",
        "live_badge": "LIVE CHECK",
        "preview_badge": "SAMPLE PREVIEW",
        "risk_score": "risk score",
        "evidence_heading": "What we noticed",
        "ml_caption": "ML confidence signal: {pct:.1f}% phishing similarity (supporting evidence only, not a verdict by itself).",
        "campaign_warn": "Repeated scam/campaign pattern detected across recent scans.",
        "preview_label": "Preview sample result:",
        "preview_opts": ["None (Live)", "Low Risk", "Suspicious", "Dangerous"],
        "recent_title": "Recent checks in this session",
        "problem_eyebrow": "THE PROBLEM WE’RE SOLVING",
        "problem_title": "Scams are getting more convincing. Knowing what to trust shouldn’t be hard.",
        "threats": [
            ("Fake KYC & bank alerts", "Messages that pressure you to “verify now” or share an OTP."),
            ("Impersonation links", "Look-alike websites designed to resemble familiar brands."),
            ("Prize, parcel & job scams", "Unexpected rewards, delivery fees, and suspicious offers."),
        ],
        "how_eyebrow": "SIMPLE BY DESIGN",
        "how_title": "A safer pause in four steps.",
        "steps": [
            ("01 • Paste", "Copy in a suspicious link, SMS, or chat message."),
            ("02 • Analyze", "PhishShield checks the submitted text for warning signs."),
            ("03 • Understand", "Get a clear risk level and plain-language explanation."),
            ("04 • Choose carefully", "Use the evidence to decide your next step without rushing."),
        ],
        "guide_eyebrow": "READ THE RESULT",
        "guide_title": "Three levels. One clearer decision.",
        "tiers": [
            ("00—24", "Low Risk (Unverified)", "No strong warning signs found. Still unverified, not guaranteed safe.", "ps-tier-low"),
            ("25—59", "Suspicious", "Some signals deserve caution. Verify through an official channel.", "ps-tier-sus"),
            ("60—100", "Dangerous", "Strong scam indicators detected. Do not share OTPs or engage.", "ps-tier-dan"),
        ],
        "faq_eyebrow": "GOOD TO KNOW",
        "faq_title": "A few things you might be wondering.",
        "faqs": [
            ("Does PhishShield open the link?", "No. Submitted URLs are treated strictly as text and never fetched or executed."),
            ("Does “Low Risk” mean safe?", "No. It means no strong warning signs were found in the text; unknown links remain unverified."),
            ("Can it check messages as well as URLs?", "Yes. You can paste SMS, WhatsApp alerts, KYC notices, parcel updates, and job offers."),
        ],
        "footer": "PhishShield analyzes text only. Never open, fetch, or share OTPs with unverified links.",
        "min_chars_err": "Please enter at least 3 characters to scan.",
    },
    "hi": {
        "tagline": "क्लिक करने से पहले जाँचें।",
        "private": "गोपनीयता-प्रथम डिज़ाइन",
        "eyebrow": "संदिग्ध संदेश जाँचने का शांत और सुरक्षित तरीका",
        "hero_top": "क्लिक करने से पहले,",
        "hero_accent": "एक बार जाँच लें।",
        "hero_sub": "संदिग्ध लिंक या संदेश का टेक्स्ट यहाँ पेस्ट करें। हम लिंक खोले बिना उसके खतरे के संकेत दिखाते हैं।",
        "trust": [
            ("ज़ीरो-क्लिक", "सिर्फ़ टेक्स्ट जाँच"),
            ("English व हिन्दी", "सरल भाषा में समझ"),
            ("कोई IP सेव नहीं", "सुरक्षित गोपनीय लॉग"),
        ],
        "hero_card_title": "सिर्फ़ टेक्स्ट। कोई लिंक नहीं खुलता।",
        "hero_card_sub": "स्पष्ट नियम + UCI-प्रशिक्षित ML संकेत + लोकल Qwen व्याख्या।",
        "your_check": "आपकी जाँच",
        "check_heading": "क्या संदिग्ध लग रहा है?",
        "demo_caption": "सुरक्षित उदाहरण आज़माएं (केवल टेक्स्ट भरता है, लिंक नहीं खोलता):",
        "demos": [
            ("कम जोखिम URL", "https://www.example.com"),
            ("KYC + OTP ठगी", "Your KYC will expire today. Verify now at http://198.51.100.42/login and share your OTP."),
            ("नकली ब्रांड लिंक", "https://paypal-verify.example/account/login"),
            ("छोटा किया लिंक", "http://bit.ly/verify-prize-now"),
        ],
        "input_label": "संदिग्ध URL या संदेश",
        "placeholder": "कोई URL, SMS, WhatsApp संदेश, KYC अलर्ट, पार्सल अपडेट या नौकरी का ऑफर पेस्ट करें…",
        "check_btn": "Check safely",
        "remember": "याद रखें: “कम जोखिम (असत्यापित)” का अर्थ है कि बड़े टेक्स्ट संकेत नहीं मिले—यह किसी असत्यापित साइट के सुरक्षित होने की गारंटी नहीं है।",
        "your_result": "आपका परिणाम",
        "result_heading": "सरल और साफ़ जानकारी।",
        "live_badge": "लाइव जाँच",
        "preview_badge": "उदाहरण पूर्वावलोकन",
        "risk_score": "जोखिम स्कोर",
        "evidence_heading": "हमने क्या देखा",
        "ml_caption": "ML मॉडल संकेत: {pct:.1f}% फ़िशिंग समानता (केवल सहायक संकेत, अकेले अंतिम निर्णय नहीं)।",
        "campaign_warn": "हाल की जाँचों में बार-बार दोहराया जाने वाला स्कैम पैटर्न मिला।",
        "preview_label": "परिणाम का उदाहरण देखें:",
        "preview_opts": ["None (Live)", "Low Risk", "Suspicious", "Dangerous"],
        "recent_title": "इस सत्र की हाल की जाँचें",
        "problem_eyebrow": "हम किस समस्या को हल कर रहे हैं",
        "problem_title": "ऑनलाइन ठगी लगातार बढ़ रही है। क्या सही है यह समझना कठिन नहीं होना चाहिए।",
        "threats": [
            ("नकली KYC व बैंक अलर्ट", "ऐसे संदेश जो तुरंत “verify” करने या OTP बताने का दबाव डालते हैं।"),
            ("नकली ब्रांड लिंक", "असली जैसी दिखने वाली वेबसाइटें जो भरोसेमंद कंपनियों की नकल करती हैं।"),
            ("इनाम, पार्सल व नौकरी ठगी", "अनपेक्षित इनाम, डिलीवरी शुल्क और संदिग्ध ऑफर वाले संदेश।"),
        ],
        "how_eyebrow": "सरल और सुरक्षित प्रक्रिया",
        "how_title": "चार आसान चरणों में सुरक्षित जाँच।",
        "steps": [
            ("01 • पेस्ट करें", "संदिग्ध लिंक, SMS या चैट संदेश यहाँ डालें।"),
            ("02 • विश्लेषण", "PhishShield बिना लिंक खोले टेक्स्ट में खतरे के संकेत खोजता है।"),
            ("03 • समझें", "स्पष्ट जोखिम स्तर और आसान हिन्दी में व्याख्या पाएं।"),
            ("04 • सोचकर निर्णय लें", "जल्दबाज़ी किए बिना सबूत के आधार पर अगला कदम तय करें।"),
        ],
        "guide_eyebrow": "परिणाम को समझें",
        "guide_title": "तीन स्तर। एक स्पष्ट निर्णय।",
        "tiers": [
            ("00—24", "कम जोखिम (असत्यापित)", "बड़े खतरे के संकेत नहीं मिले। फिर भी लिंक असत्यापित है, पूरी तरह सुरक्षित नहीं।", "ps-tier-low"),
            ("25—59", "संदिग्ध (Suspicious)", "कुछ संकेत सावधानी बरतने को कहते हैं। आधिकारिक स्रोत से पुष्टि करें।", "ps-tier-sus"),
            ("60—100", "खतरनाक (Dangerous)", "ठगी के मज़बूत संकेत मिले हैं। OTP साझा न करें और लिंक न खोलें।", "ps-tier-dan"),
        ],
        "faq_eyebrow": "अक्सर पूछे जाने वाले सवाल",
        "faq_title": "कुछ बातें जो आप जानना चाहेंगे।",
        "faqs": [
            ("क्या PhishShield लिंक को खोलता है?", "नहीं। डाले गए URL को केवल टेक्स्ट के रूप में देखा जाता है; वेबसाइट कभी नहीं खोली जाती।"),
            ("क्या “कम जोखिम” का मतलब सुरक्षित है?", "नहीं। इसका मतलब है कि टेक्स्ट में आम ठगी के संकेत नहीं मिले; अनजान लिंक असत्यापित रहते हैं।"),
            ("क्या यह URL के अलावा पूरे संदेश भी जाँच सकता है?", "हाँ। आप SMS, WhatsApp संदेश, KYC नोटिस, पार्सल अपडेट या नौकरी के ऑफर पेस्ट कर सकते हैं।"),
        ],
        "footer": "PhishShield केवल टेक्स्ट का विश्लेषण करता है। कभी भी अनजान लिंक न खोलें और न ही OTP साझा करें।",
        "min_chars_err": "जाँचने के लिए कम से कम 3 अक्षर दर्ज करें।",
    },
}

SAMPLE_OUTCOMES = {
    "Low Risk": ScanOutcome(
        scan_reference="261127000101",
        risk_score=0,
        risk_level="Low Risk",
        content_type="url",
        reasons=["No common phishing indicators were found in the text, though the destination itself is unverified."],
        explanation="We did not find strong warning signs in this text. That does not prove the destination is safe—this link is still unverified.",
        ml_probability=0.0054,
        campaign_detected=False,
    ),
    "Suspicious": ScanOutcome(
        scan_reference="261127000102",
        risk_score=40,
        risk_level="Suspicious",
        content_type="url",
        reasons=[
            "The link does not use HTTPS, so its connection may not be protected.",
            "This is a shortened link, which can hide its real destination.",
        ],
        explanation="This link has warning signs. Shortened non-HTTPS links can hide where they actually lead—verify before trusting.",
        ml_probability=0.71,
        campaign_detected=False,
    ),
    "Dangerous": ScanOutcome(
        scan_reference="261127000103",
        risk_score=100,
        risk_level="Dangerous",
        content_type="message",
        reasons=[
            "The message uses scam-associated language: kyc, otp, urgent, verify.",
            "The message asks for sensitive authentication or payment information.",
            "The link uses a raw IP address instead of a normal website name.",
        ],
        explanation="This message shows strong scam indicators: urgency, OTP request, and a raw IP link. Do not click the link or share your OTP.",
        ml_probability=0.98,
        campaign_detected=True,
    ),
}


def _render_gauge(outcome: ScanOutcome, score_label: str, mode_badge: str) -> str:
    score = max(0, min(100, int(outcome.risk_score)))
    radius = 48
    circ = 2 * 3.14159265 * radius
    progress = circ * (score / 100.0)
    color = "#70ddbd" if outcome.risk_level == "Low Risk" else ("#ffce77" if outcome.risk_level == "Suspicious" else "#ff8b89")
    ref = html.escape(str(outcome.scan_reference))
    ctype = html.escape(str(outcome.content_type).upper())
    badge = html.escape(mode_badge)
    lbl = html.escape(score_label)
    return f"""
    <div class="ps-gauge-wrap">
      <div class="ps-gauge">
        <svg viewBox="0 0 120 120">
          <circle cx="60" cy="60" r="{radius}" fill="none" stroke="#21364a" stroke-width="8" />
          <circle cx="60" cy="60" r="{radius}" fill="none" stroke="{color}" stroke-width="8"
            stroke-linecap="round" stroke-dasharray="{progress:.1f} {circ:.1f}" />
        </svg>
        <div class="ps-gauge-center">
          <strong>{score}<small>/100</small></strong>
          <span>{lbl}</span>
        </div>
      </div>
      <div>
        <div class="ps-ref-pill">{badge} • SCAN REF: {ref}</div>
        <div style="margin-top:6px;font-size:13px;color:#b7c8d6;">Type: <b>{ctype}</b></div>
      </div>
    </div>
    """


@st.cache_resource
def _init_db() -> bool:
    initialize_database()
    return True


_init_db()
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

if "client_id" not in st.session_state:
    st.session_state.client_id = f"st-{uuid.uuid4().hex[:12]}"
if "scan_input" not in st.session_state:
    st.session_state.scan_input = ""
if "scan_history" not in st.session_state:
    st.session_state.scan_history = []
if "last_outcome" not in st.session_state:
    st.session_state.last_outcome = None
if "last_error" not in st.session_state:
    st.session_state.last_error = ""

top_left, top_right = st.columns([4, 1])
with top_right:
    language_label = st.selectbox(
        "Explanation language",
        ["English", "Hindi"],
        format_func=lambda opt: "हिन्दी" if opt == "Hindi" else opt,
        label_visibility="collapsed",
    )

lang_code = "hi" if language_label == "Hindi" else "en"
t = COPY[lang_code]

with top_left:
    st.markdown(
        f"""
        <div class="ps-topbar">
          <div class="ps-brand">
            <span class="ps-brand-mark">🛡️</span>
            <div>phish<span class="accent">shield</span><small>{html.escape(t['tagline'])}</small></div>
          </div>
          <span class="ps-privacy-pill"><span class="ps-dot"></span>{html.escape(t['private'])}</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

trust_html = "".join(
    f'<div class="ps-trust-chip"><b>{html.escape(title)}</b><span>{html.escape(sub)}</span></div>'
    for title, sub in t["trust"]
)
st.markdown(
    f"""
    <section class="ps-hero">
      <div>
        <div class="ps-eyebrow">{html.escape(t['eyebrow'])}</div>
        <h1>{html.escape(t['hero_top'])}<br/><em>{html.escape(t['hero_accent'])}</em></h1>
        <p class="ps-hero-sub">{html.escape(t['hero_sub'])}</p>
        <div class="ps-trust-row">{trust_html}</div>
      </div>
      <div class="ps-hero-card">
        <div class="ps-hero-shield">✓</div>
        <b>{html.escape(t['hero_card_title'])}</b>
        <p>{html.escape(t['hero_card_sub'])}</p>
      </div>
    </section>
    """,
    unsafe_allow_html=True,
)

col_input, col_result = st.columns([1, 1], gap="large")

with col_input:
    st.markdown(f"<div class='ps-eyebrow'>{html.escape(t['your_check'])}</div>", unsafe_allow_html=True)
    st.subheader(t["check_heading"])
    st.caption(t["demo_caption"])

    demo_cols = st.columns(4)
    for idx, (label, val) in enumerate(t["demos"]):
        if demo_cols[idx].button(label, use_container_width=True, key=f"demo_{idx}"):
            st.session_state.scan_input = val
            st.session_state.last_error = ""

    with st.form("scan_form"):
        content = st.text_area(
            t["input_label"],
            key="scan_input",
            height=150,
            max_chars=5000,
            placeholder=t["placeholder"],
        )
        submitted = st.form_submit_button(t["check_btn"], type="primary", use_container_width=True)

    st.caption(t["remember"])

if submitted:
    trimmed = content.strip()
    st.session_state.last_error = ""
    if len(trimmed) < 3:
        st.session_state.last_error = t["min_chars_err"]
        st.session_state.last_outcome = None
    else:
        try:
            outcome = run_scan_pipeline(trimmed, lang_code, st.session_state.client_id)
        except HTTPException as exc:
            st.session_state.last_error = str(exc.detail)
            st.session_state.last_outcome = None
        else:
            st.session_state.last_outcome = outcome
            st.session_state.scan_history = [
                {
                    "ref": outcome.scan_reference,
                    "level": outcome.risk_level,
                    "score": outcome.risk_score,
                    "preview": trimmed[:80],
                },
                *st.session_state.scan_history,
            ][:4]

with col_result:
    st.markdown(f"<div class='ps-eyebrow'>{html.escape(t['your_result'])}</div>", unsafe_allow_html=True)
    st.subheader(t["result_heading"])

    if st.session_state.last_error:
        st.error(st.session_state.last_error)

    preview_choice = "None (Live)"
    if st.session_state.last_outcome is None and not st.session_state.last_error:
        preview_choice = st.selectbox(
            t["preview_label"],
            t["preview_opts"],
            index=3,
            key="sample_preview_select",
        )

    display_outcome = st.session_state.last_outcome
    mode_badge = t["live_badge"]
    if display_outcome is None and preview_choice != "None (Live)":
        display_outcome = SAMPLE_OUTCOMES.get(preview_choice)
        mode_badge = t["preview_badge"]

    if display_outcome is not None:
        st.markdown(_render_gauge(display_outcome, t["risk_score"], mode_badge), unsafe_allow_html=True)

        if display_outcome.risk_level == "Dangerous":
            st.error(f"Verdict: **{display_outcome.risk_level}** ({display_outcome.risk_score}/100)")
        elif display_outcome.risk_level == "Suspicious":
            st.warning(f"Verdict: **{display_outcome.risk_level}** ({display_outcome.risk_score}/100)")
        else:
            st.success(f"Verdict: **Low Risk (Unverified)** ({display_outcome.risk_score}/100)")

        if display_outcome.campaign_detected:
            st.warning(t["campaign_warn"])

        st.info(display_outcome.explanation)

        st.markdown(f"**{t['evidence_heading']}**")
        for reason in display_outcome.reasons:
            st.markdown(f"- {reason}")

        if display_outcome.ml_probability is not None:
            st.progress(max(0.0, min(1.0, float(display_outcome.ml_probability))))
            st.caption(t["ml_caption"].format(pct=display_outcome.ml_probability * 100))

    if st.session_state.scan_history:
        with st.expander(t["recent_title"]):
            for item in st.session_state.scan_history:
                st.markdown(f"- **{item['level']} ({item['score']}/100)** `{item['ref']}` — {item['preview']}")

# Story, 4-step walkthrough, 3-tier guide, and FAQ sections
threats_html = "".join(
    f'<div class="ps-info-card"><b>{html.escape(title)}</b><p>{html.escape(desc)}</p></div>'
    for title, desc in t["threats"]
)
steps_html = "".join(
    f'<div class="ps-info-card"><b>{html.escape(title)}</b><p>{html.escape(desc)}</p></div>'
    for title, desc in t["steps"]
)
tiers_html = "".join(
    f'<div class="ps-info-card {cls}"><span class="ps-tier-range">{html.escape(rng)}</span><b>{html.escape(lbl)}</b><p>{html.escape(desc)}</p></div>'
    for rng, lbl, desc, cls in t["tiers"]
)
faqs_html = "".join(
    f'<div class="ps-info-card"><b>{html.escape(q)}</b><p>{html.escape(a)}</p></div>'
    for q, a in t["faqs"]
)

st.markdown(
    f"""
    <section class="ps-section-divider">
      <div class="ps-eyebrow">{html.escape(t['problem_eyebrow'])}</div>
      <h3>{html.escape(t['problem_title'])}</h3>
      <div class="ps-card-grid-3">{threats_html}</div>
    </section>
    <section class="ps-section-divider">
      <div class="ps-eyebrow">{html.escape(t['how_eyebrow'])}</div>
      <h3>{html.escape(t['how_title'])}</h3>
      <div class="ps-card-grid-4">{steps_html}</div>
    </section>
    <section class="ps-section-divider">
      <div class="ps-eyebrow">{html.escape(t['guide_eyebrow'])}</div>
      <h3>{html.escape(t['guide_title'])}</h3>
      <div class="ps-card-grid-3">{tiers_html}</div>
    </section>
    <section class="ps-section-divider">
      <div class="ps-eyebrow">{html.escape(t['faq_eyebrow'])}</div>
      <h3>{html.escape(t['faq_title'])}</h3>
      <div class="ps-card-grid-3">{faqs_html}</div>
    </section>
    """,
    unsafe_allow_html=True,
)

st.caption(t["footer"])

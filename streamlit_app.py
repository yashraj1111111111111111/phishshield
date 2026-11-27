"""Streamlit entrypoint for standalone and Streamlit Community Cloud deployment."""
from __future__ import annotations

import html
import uuid

import streamlit as st
from fastapi import HTTPException

from app.database.connection import initialize_database
from app.services.scan_pipeline import ScanOutcome, run_scan_pipeline

st.set_page_config(page_title="PhishShield — Check Before You Click", page_icon="🛡️", layout="wide")

THEMES = {
    "Dark": {
        "bg": "#07111f",
        "bg_grad": "rgba(24, 217, 210, 0.16)",
        "header_bg": "rgba(7, 17, 31, 0.92)",
        "card": "#0b1c31",
        "card_hover": "#132a46",
        "card_grad": "linear-gradient(145deg, #0e243b, #091829)",
        "input_bg": "#071728",
        "form_bg": "rgba(11, 28, 49, 0.72)",
        "text": "#eaf2f8",
        "heading": "#f3f7fa",
        "muted": "#9eb0c0",
        "subtle": "#8da2b3",
        "accent": "#18D9D2",
        "accent_purple": "#A855F7",
        "accent_ink": "#07111f",
        "accent_soft": "rgba(24, 217, 210, 0.12)",
        "border": "rgba(24, 217, 210, 0.15)",
        "track": "#132a46",
        "low": "#70ddbd",
        "suspicious": "#ffce77",
        "dangerous": "#ff8b89",
        "alert_bg": "rgba(14, 34, 56, 0.92)",
    },
    "Light": {
        "bg": "#f4f7fb",
        "bg_grad": "rgba(12, 138, 114, 0.10)",
        "header_bg": "rgba(244, 247, 251, 0.90)",
        "card": "#ffffff",
        "card_hover": "#eaf2f8",
        "card_grad": "linear-gradient(145deg, #ffffff, #eef4fa)",
        "input_bg": "#ffffff",
        "form_bg": "rgba(255, 255, 255, 0.94)",
        "text": "#0f2236",
        "heading": "#091829",
        "muted": "#41566c",
        "subtle": "#52687e",
        "accent": "#0c8a72",
        "accent_ink": "#ffffff",
        "accent_soft": "rgba(12, 138, 114, 0.10)",
        "border": "rgba(15, 34, 54, 0.15)",
        "track": "#dce6f0",
        "low": "#0c8a72",
        "suspicious": "#b86e00",
        "dangerous": "#c83737",
        "alert_bg": "#ffffff",
    },
}


def _build_css(theme_name: str) -> str:
    p = THEMES.get(theme_name, THEMES["Dark"])
    return f"""
<style>
  @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;700&family=Manrope:wght@600;700;800&display=swap');

  .stApp {{
    background: radial-gradient(ellipse at 15% 5%, {p['bg_grad']}, transparent 36%), {p['bg']};
    color: {p['text']};
    font-family: 'DM Sans', ui-sans-serif, system-ui, sans-serif;
  }}
  header[data-testid="stHeader"],
  [data-testid="stToolbar"] {{
    display: none !important;
  }}
  .block-container {{
    max-width: 1180px;
    padding-top: 1.4rem;
    padding-bottom: 2.5rem;
  }}
  h1, h2, h3, h4, .stMarkdown p, .stMarkdown li {{
    color: {p['text']};
  }}
  h1, h2, h3, h4 {{
    font-family: 'Manrope', ui-sans-serif, system-ui, sans-serif;
    color: {p['heading']};
  }}
  .ps-topbar {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding-bottom: 14px;
    border-bottom: 1px solid {p['border']};
    margin-bottom: 18px;
    position: relative;
  }}
  .ps-topbar::after {{
    content: '';
    position: absolute;
    bottom: -1px;
    left: 0;
    right: 0;
    height: 1px;
    background: linear-gradient(90deg, #18D9D2, #A855F7 60%, transparent);
  }}
  .ps-brand {{
    display: flex;
    align-items: center;
    gap: 11px;
    font: 800 20px/1 'Manrope', sans-serif;
    color: {p['heading']};
  }}
  .ps-brand-mark {{
    width: 36px;
    height: 36px;
    border-radius: 11px;
    display: grid;
    place-items: center;
    background: linear-gradient(135deg, rgba(24, 217, 210, 0.2), rgba(168, 85, 247, 0.2));
    border: 1px solid rgba(24, 217, 210, 0.4);
    color: {p['accent']};
  }}
  .ps-brand small {{
    display: block;
    margin-top: 4px;
    color: {p['subtle']};
    font: 700 9px/1 'DM Sans', sans-serif;
    letter-spacing: 1.7px;
  }}
  .ps-brand .accent {{
    background: linear-gradient(135deg, #18D9D2, #A855F7);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
  }}
  .ps-privacy-pill {{
    display: inline-flex;
    align-items: center;
    gap: 8px;
    font-size: 12px;
    color: {p['muted']};
    padding: 6px 12px;
    border-radius: 999px;
    border: 1px solid {p['border']};
    background: {p['card']};
  }}
  .ps-dot {{
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: {p['accent']};
  }}
  .ps-hero {{
    display: grid;
    grid-template-columns: 1.25fr 0.75fr;
    gap: 28px;
    align-items: center;
    padding: 18px 0 26px;
  }}
  .ps-eyebrow {{
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 1.6px;
    color: {p['accent']};
    text-transform: uppercase;
    margin-bottom: 10px;
  }}
  .ps-hero h1 {{
    font-size: clamp(2.1rem, 4.2vw, 3.3rem);
    line-height: 1.1;
    letter-spacing: -0.04em;
    margin: 0 0 12px;
    color: {p['heading']};
  }}
  .ps-hero h1 em {{
    font-style: normal;
    background: linear-gradient(135deg, #18D9D2 0%, #A855F7 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
  }}
  .ps-hero-sub {{
    color: {p['muted']};
    font-size: 15px;
    line-height: 1.65;
    max-width: 560px;
    margin-bottom: 18px;
  }}
  .ps-trust-row {{
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
  }}
  .ps-trust-chip {{
    background: {p['card']};
    border: 1px solid {p['border']};
    border-radius: 10px;
    padding: 8px 12px;
    font-size: 12px;
    color: {p['heading']};
  }}
  .ps-trust-chip span {{ display: block; font-size: 10px; color: {p['subtle']}; margin-top: 2px; }}
  .ps-hero-card {{
    background: {p['card_grad']};
    border: 1px solid {p['border']};
    border-radius: 16px;
    padding: 22px;
    text-align: center;
    box-shadow: 0 14px 36px rgba(2, 8, 20, 0.14);
  }}
  .ps-hero-shield {{
    width: 72px;
    height: 78px;
    margin: 0 auto 12px;
    display: grid;
    place-items: center;
    background: linear-gradient(135deg, rgba(24, 217, 210, 0.15), rgba(168, 85, 247, 0.15));
    border: 1px solid rgba(24, 217, 210, 0.4);
    clip-path: polygon(50% 0, 91% 16%, 88% 66%, 50% 100%, 12% 66%, 9% 16%);
    color: #18D9D2;
    font-size: 28px;
    font-weight: 800;
  }}
  .ps-hero-card p {{ font-size: 12px; color: {p['muted']}; margin: 4px 0 0; }}
  .ps-section-divider {{
    border-top: 1px solid {p['border']};
    margin: 24px 0 20px;
    padding-top: 22px;
  }}
  .ps-card-grid-3 {{
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 12px;
    margin-top: 14px;
  }}
  .ps-card-grid-4 {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 12px;
    margin-top: 14px;
  }}
  .ps-info-card {{
    background: {p['card']};
    border: 1px solid {p['border']};
    border-radius: 12px;
    padding: 15px;
  }}
  .ps-info-card b {{ display: block; font-size: 13px; color: {p['heading']}; margin-bottom: 6px; }}
  .ps-info-card p {{ font-size: 12px; line-height: 1.55; color: {p['subtle']}; margin: 0; }}
  .ps-tier-low {{ border-top: 3px solid {p['low']}; }}
  .ps-tier-low .ps-tier-range {{ color: {p['low']}; }}
  .ps-tier-sus {{ border-top: 3px solid {p['suspicious']}; }}
  .ps-tier-sus .ps-tier-range {{ color: {p['suspicious']}; }}
  .ps-tier-dan {{ border-top: 3px solid {p['dangerous']}; }}
  .ps-tier-dan .ps-tier-range {{ color: {p['dangerous']}; }}
  .ps-tier-range {{ font: 800 16px/1 'Manrope', sans-serif; margin-bottom: 8px; display: block; }}

  .ps-gauge-wrap {{
    display: flex;
    align-items: center;
    gap: 18px;
    background: {p['card_grad']};
    border: 1px solid {p['border']};
    border-radius: 14px;
    padding: 16px;
    margin-bottom: 12px;
  }}
  .ps-gauge {{
    position: relative;
    width: 118px;
    height: 118px;
    flex: none;
  }}
  .ps-gauge svg {{ width: 100%; height: 100%; transform: rotate(-90deg); }}
  .ps-gauge-center {{
    position: absolute;
    inset: 0;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    line-height: 1.1;
  }}
  .ps-gauge-center strong {{ font: 800 26px 'Manrope', sans-serif; color: {p['heading']}; }}
  .ps-gauge-center small {{ font-size: 11px; color: {p['subtle']}; }}
  .ps-gauge-center span {{ font-size: 10px; color: {p['subtle']}; margin-top: 2px; }}
  .ps-ref-pill {{
    font-size: 11px;
    letter-spacing: 0.9px;
    color: {p['accent']};
    font-weight: 700;
  }}
  .stButton > button[kind="primary"],
  [data-testid="stFormSubmitButton"] > button {{
    background: linear-gradient(135deg, #18D9D2 0%, #A855F7 100%) !important;
    color: #07111f !important;
    border: 0 !important;
    font-weight: 800 !important;
    box-shadow: 0 4px 18px rgba(24, 217, 210, 0.25) !important;
  }}
  div[data-testid="stProgressBar"] > div > div {{
    background: linear-gradient(90deg, #18D9D2 0%, #A855F7 100%) !important;
  }}
  .stButton > button:not([kind="primary"]) {{
    background: {p['card']} !important;
    color: {p['text']} !important;
    border: 1px solid {p['border']} !important;
    border-radius: 9px !important;
    font-weight: 600 !important;
  }}
  .stButton > button:not([kind="primary"]):hover {{
    background: {p['card_hover']} !important;
    border-color: {p['accent']} !important;
    color: {p['heading']} !important;
  }}
  [data-testid="stForm"] {{
    background: {p['form_bg']} !important;
    border: 1px solid {p['border']} !important;
    border-radius: 14px !important;
    padding: 16px !important;
  }}
  .stTextArea label,
  .stSelectbox label,
  [data-testid="stCaptionContainer"] p {{
    color: {p['muted']} !important;
  }}
  .stTextArea textarea {{
    background-color: {p['input_bg']} !important;
    color: {p['text']} !important;
    border-color: {p['border']} !important;
  }}
  .stTextArea textarea::placeholder {{
    color: {p['subtle']} !important;
    opacity: 1 !important;
  }}
  div[data-baseweb="select"] > div {{
    background-color: {p['card']} !important;
    border-color: {p['border']} !important;
    color: {p['text']} !important;
  }}
  div[data-baseweb="select"] svg {{
    fill: {p['muted']} !important;
  }}
  [data-testid="stAlert"] {{
    background-color: {p['alert_bg']} !important;
    color: {p['text']} !important;
    border: 1px solid {p['border']} !important;
  }}
  [data-testid="stAlert"] p {{
    color: {p['text']} !important;
  }}
  [data-testid="stExpander"] {{
    background-color: {p['card']} !important;
    border: 1px solid {p['border']} !important;
    border-radius: 10px !important;
  }}
  [data-testid="stExpander"] summary {{
    color: {p['heading']} !important;
  }}
  @media (max-width: 780px) {{
    .ps-hero, .ps-card-grid-3, .ps-card-grid-4 {{ grid-template-columns: 1fr; }}
  }}
</style>
"""


COPY = {
    "en": {
        "tagline": "CHECK BEFORE YOU CLICK.",
        "private": "Private by design",
        "theme_labels": {"Dark": "🌙 Dark", "Light": "☀️ Light"},
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
        "placeholder": "Paste a URL, SMS, Digital Arrest threat, UPI/QR request, e-challan .apk, KYC alert…",
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
            ("Digital Arrest, KYC & OTP scams", "Fake CBI, customs, or TRAI threats, KYC expiry alerts, and screen-sharing traps (AnyDesk/TeamViewer)."),
            ("UPI, QR & impersonation links", "Tricks asking for your UPI PIN or QR scan to receive money, plus look-alike bank/gov URLs and risky domains."),
            ("Malicious .APK, challan & prize scams", "Fake RTO e-challan or PM-Kisan .apk downloads, parcel fees, and unexpected rewards."),
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
            ("Can it check messages as well as URLs?", "Yes. You can paste SMS, WhatsApp alerts, Digital Arrest/CBI threats, UPI/QR refund messages, e-challan .apk links, KYC notices, and job offers."),
        ],
        "footer": "PhishShield analyzes text only. Never open, fetch, or share OTPs with unverified links.",
        "min_chars_err": "Please enter at least 3 characters to scan.",
    },
    "hi": {
        "tagline": "क्लिक करने से पहले जाँचें।",
        "private": "गोपनीयता-प्रथम डिज़ाइन",
        "theme_labels": {"Dark": "🌙 डार्क", "Light": "☀️ लाइट"},
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
        "placeholder": "कोई URL, SMS, डिजिटल अरेस्ट धमकी, UPI/QR संदेश, ई-चालान .apk या KYC अलर्ट पेस्ट करें…",
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
            ("डिजिटल अरेस्ट, KYC व OTP ठगी", "नकली CBI/कस्टम या TRAI धमकी, KYC बंद होने के अलर्ट, और स्क्रीन-शेयरिंग (AnyDesk/TeamViewer) जाल।"),
            ("UPI, QR व नकली ब्रांड लिंक", "पैसे पाने के नाम पर UPI PIN या QR स्कैन कराने की चाल, नकली बैंक/सरकारी लिंक और संदिग्ध डोमेन।"),
            ("खतरनाक .APK, ई-चालान व इनाम ठगी", "नकली RTO ई-चालान या PM-Kisan .apk डाउनलोड, पार्सल शुल्क और अनपेक्षित इनाम।"),
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
            ("क्या यह URL के अलावा पूरे संदेश भी जाँच सकता है?", "हाँ। आप SMS, WhatsApp संदेश, डिजिटल अरेस्ट/CBI धमकी, UPI/QR रिफंड, ई-चालान .apk लिंक, KYC नोटिस या नौकरी के ऑफर पेस्ट कर सकते हैं।"),
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
        reasons=["No common phishing indicators were found in the text, though the destination itself is unverified and not guaranteed to be safe."],
        explanation=(
            "Low Risk (Unverified) means no strong warning signs were found by this text-only scan. "
            "It does not prove that this website or message is genuine or safe—verify important requests through the organisation's official app, bookmarked website, or a known contact method."
        ),
        ml_probability=0.0054,
        campaign_detected=False,
        technical_details={
            "parsed_host": "www.example.com",
            "host_type": "domain",
            "port": "Not specified",
            "scheme": "https",
            "https": "yes",
            "top_level_domain": ".com",
            "url_length": 23,
            "subdomain_count": 1,
            "detected_url_indicators": [],
            "detected_message_indicators": [],
            "triggered_rules": [],
        },
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
        technical_details={
            "parsed_host": "bit.ly",
            "host_type": "domain",
            "port": "Not specified",
            "scheme": "http",
            "https": "no",
            "top_level_domain": ".ly",
            "url_length": 29,
            "subdomain_count": 0,
            "detected_url_indicators": [
                "The link does not use HTTPS, so its connection may not be protected.",
                "This is a shortened link, which can hide its real destination.",
            ],
            "detected_message_indicators": [],
            "triggered_rules": [
                {"rule_id": "url_no_https", "category": "url", "score": 15, "reason": "The link does not use HTTPS, so its connection may not be protected."},
                {"rule_id": "url_shortener", "category": "url", "score": 20, "reason": "This is a shortened link, which can hide its real destination."},
            ],
        },
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
        technical_details={
            "parsed_host": "198.51.100.42",
            "host_type": "ip_address",
            "port": "Not specified",
            "scheme": "http",
            "https": "no",
            "top_level_domain": "Not applicable (IP address)",
            "url_length": 27,
            "subdomain_count": 0,
            "detected_url_indicators": ["The link uses a raw IP address instead of a normal website name."],
            "detected_message_indicators": [
                "The message uses scam-associated language: kyc, otp, urgent, verify.",
                "The message asks for sensitive authentication or payment information.",
            ],
            "triggered_rules": [
                {"rule_id": "msg_scam_keywords", "category": "message", "score": 24, "reason": "The message uses scam-associated language: kyc, otp, urgent, verify."},
                {"rule_id": "msg_sensitive_info", "category": "message", "score": 30, "reason": "The message asks for sensitive authentication or payment information."},
                {"rule_id": "url_raw_ip", "category": "url", "score": 30, "reason": "The link uses a raw IP address instead of a normal website name."},
            ],
        },
    ),
}


def _render_gauge(outcome: ScanOutcome, score_label: str, mode_badge: str, theme_name: str) -> str:
    p = THEMES.get(theme_name, THEMES["Dark"])
    score = max(0, min(100, int(outcome.risk_score)))
    radius = 48
    circ = 2 * 3.14159265 * radius
    progress = circ * (score / 100.0)
    color = p["low"] if outcome.risk_level == "Low Risk" else (p["suspicious"] if outcome.risk_level == "Suspicious" else p["dangerous"])
    ref = html.escape(str(outcome.scan_reference))
    ctype = html.escape(str(outcome.content_type).upper())
    badge = html.escape(mode_badge)
    lbl = html.escape(score_label)
    return f"""
    <div class="ps-gauge-wrap">
      <div class="ps-gauge">
        <svg viewBox="0 0 120 120">
          <circle cx="60" cy="60" r="{radius}" fill="none" stroke="{p['track']}" stroke-width="8" />
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
        <div style="margin-top:6px;font-size:13px;color:{p['muted']};">Type: <b>{ctype}</b></div>
      </div>
    </div>
    """


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
if "last_outcome" not in st.session_state:
    st.session_state.last_outcome = None
if "last_error" not in st.session_state:
    st.session_state.last_error = ""

top_left, top_lang, top_theme = st.columns([3.2, 0.9, 0.9])
with top_lang:
    language_label = st.selectbox(
        "Explanation language",
        ["English", "Hindi"],
        format_func=lambda opt: "हिन्दी" if opt == "Hindi" else opt,
        label_visibility="collapsed",
    )

lang_code = "hi" if language_label == "Hindi" else "en"
t = COPY[lang_code]

with top_theme:
    theme_choice = st.selectbox(
        "Theme",
        ["Dark", "Light"],
        format_func=lambda opt: t["theme_labels"].get(opt, opt),
        label_visibility="collapsed",
        key="theme_select",
    )

st.markdown(_build_css(theme_choice), unsafe_allow_html=True)

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

    demo_row1 = st.columns(2)
    demo_row2 = st.columns(2)
    demo_slots = [*demo_row1, *demo_row2]
    for idx, (label, val) in enumerate(t["demos"]):
        if demo_slots[idx].button(label, use_container_width=True, key=f"demo_{idx}"):
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
        st.markdown(_render_gauge(display_outcome, t["risk_score"], mode_badge, theme_choice), unsafe_allow_html=True)

        if display_outcome.risk_level == "Dangerous":
            st.error(f"Verdict: **{display_outcome.risk_level}** ({display_outcome.risk_score}/100)")
        elif display_outcome.risk_level == "Suspicious":
            st.warning(f"Verdict: **{display_outcome.risk_level}** ({display_outcome.risk_score}/100)")
        else:
            st.success(f"Verdict: **Low Risk (Unverified)** ({display_outcome.risk_score}/100)")
            st.caption(
                "0/100 means no common phishing indicators were detected by this text-only scan. "
                "It does not prove that this website or message is genuine—verify important requests through the organisation's official app, bookmarked website, or a known contact method."
            )

        if display_outcome.campaign_detected:
            st.warning(t["campaign_warn"])

        st.info(display_outcome.explanation)

        st.markdown(f"**{t['evidence_heading']}**")
        for reason in display_outcome.reasons:
            st.markdown(f"- {reason}")

        if display_outcome.ml_probability is not None:
            st.progress(max(0.0, min(1.0, float(display_outcome.ml_probability))))
            st.caption(t["ml_caption"].format(pct=display_outcome.ml_probability * 100))

        td = getattr(display_outcome, "technical_details", None) or {}
        if td:
            with st.expander("Technical details"):
                st.caption("Extracted strictly from submitted text — no URLs visited or DNS lookups performed.")
                st.markdown(
                    f"- **Parsed host:** `{td.get('parsed_host', 'Not specified')}`\n"
                    f"- **Host type:** `{td.get('host_type', 'not_specified')}`\n"
                    f"- **Port:** `{td.get('port', 'Not specified')}`\n"
                    f"- **Scheme:** `{td.get('scheme', 'not specified')}`\n"
                    f"- **HTTPS:** `{td.get('https', 'not specified')}`\n"
                    f"- **Top-level domain:** `{td.get('top_level_domain', 'Not applicable')}`\n"
                    f"- **URL length:** `{td.get('url_length') if td.get('url_length') is not None else 'Not applicable'}`\n"
                    f"- **Number of subdomains:** `{td.get('subdomain_count') if td.get('subdomain_count') is not None else 'Not applicable'}`"
                )
                url_inds = td.get("detected_url_indicators") or []
                msg_inds = td.get("detected_message_indicators") or []
                rules = td.get("triggered_rules") or []
                st.markdown("**Detected URL indicators:** " + (", ".join(url_inds) if url_inds else "None"))
                st.markdown("**Detected message indicators:** " + (", ".join(msg_inds) if msg_inds else "None"))
                if rules:
                    st.markdown("**Triggered rule IDs & score contributions:**")
                    for r in rules:
                        st.markdown(f"- `{r.get('rule_id')}` (`+{r.get('score')}`): {r.get('reason')}")
                else:
                    st.markdown("**Triggered rule IDs & score contributions:** None (0 points)")

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

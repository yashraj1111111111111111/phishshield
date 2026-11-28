import React, { useEffect, useMemo, useRef, useState } from "react";
import { DEFAULT_API_URL, submitScan } from "./api.js";
import "./PhishShield.css";

const API_URL = import.meta.env.VITE_API_URL || DEFAULT_API_URL;

const DEMOS = [
  { id: "low",             kind: "mint",   value: "https://www.example.com" },
  { id: "kyc",             kind: "amber",  value: "Your KYC will expire today. Verify now at http://198.51.100.42/login and share your OTP." },
  { id: "brand",           kind: "coral",  value: "https://paypal-verify.example/account/login" },
  { id: "short",           kind: "violet", value: "http://bit.ly/verify-prize-now" },
  { id: "digital_arrest",  kind: "coral",  value: "CBI Cyber Crime notice: Your Aadhaar parcel has been seized for money laundering. Stay on video call for digital arrest or pay fine immediately." },
  { id: "trai_sim",        kind: "amber",  value: "TRAI Alert: Your mobile SIM will be disconnected within 2 hours due to illegal activity. Verify KYC at http://trai-kyc-update.xyz/verify" },
  { id: "electricity_apk", kind: "coral",  value: "MSEDCL Alert: Your electricity power will be disconnected tonight. Install official update app http://198.51.100.42/bescom-bill.apk to pay." },
  { id: "remote_access",   kind: "amber",  value: "Urgent bank refund pending. Install AnyDesk and share your 9-digit support code to receive money." },
  { id: "homograph_sbi",   kind: "violet", value: "https://s\u044ci-verify.xyz/netbanking/login" },
  { id: "zero_width",      kind: "violet", value: "Enter U\u200bPI PIN to claim reward at http://198.51.100.42:8080/login" },
  { id: "upi_cashback",    kind: "coral",  value: "Congratulations! Claim your Rs.2,500 Electricity Cashback now: upi://pay?pa=cashback-desk@okaxis&pn=ElectricityRefund&am=2500&tn=Claim%20Cashback%20Refund" },
  { id: "email_spoof",     kind: "amber",  value: "From: security@hdfcbank.com\nReply-To: helpdesk@hdfc-verify.xyz\nReturn-Path: bounce@mail-alert.top\nAuthentication-Results: spf=fail dmarc=fail\nUrgent: Update your KYC immediately." },
];

const MOCKS_BY_LANG = {
  en: {
    low: {
      scan_reference: "261127000101", risk_score: 0, risk_level: "Low Risk", content_type: "url",
      reasons: ["No common phishing indicators were found in the text, though the destination itself is unverified and not guaranteed to be safe."],
      explanation: "Low Risk (Unverified) means no strong warning signs were found. It does not prove that this website or message is genuine. New or highly convincing scams may not show visible warning signs—verify important requests through the organisation’s official app, bookmarked website, or a known contact method.",
      ml_probability: 0.08, campaign_detected: false,
      technical_details: {
        parsed_host: "www.example.com", host_type: "domain", port: "Not specified",
        scheme: "https", https: "yes", top_level_domain: ".com", url_length: 23, subdomain_count: 1,
        detected_url_indicators: [], detected_message_indicators: [], triggered_rules: [],
      },
    },
    suspicious: {
      scan_reference: "261127000102", risk_score: 46, risk_level: "Suspicious", content_type: "url",
      reasons: ["The domain contains a brand-like name with an unusual extra word.", "The URL includes a sign-in path that may be used to collect credentials."],
      explanation: "This link has a few warning signs. The address resembles a familiar service, but the domain is not that service's official domain. Do not enter a password or payment details.",
      ml_probability: 0.71, campaign_detected: false,
      technical_details: {
        parsed_host: "paypal-verify.example", host_type: "domain", port: "Not specified",
        scheme: "https", https: "yes", top_level_domain: ".example", url_length: 43, subdomain_count: 0,
        detected_url_indicators: ["Contains a well-known brand or service name ('paypal') inside an unofficial web address."],
        detected_message_indicators: [],
        triggered_rules: [{ rule_id: "url_brand_impersonation", category: "url", score: 30, reason: "Contains a well-known brand or service name ('paypal') inside an unofficial web address." }],
      },
    },
    dangerous: {
      scan_reference: "261127000103", risk_score: 94, risk_level: "Dangerous", content_type: "message",
      reasons: ["Creates urgency with a KYC-expiry threat.", "Requests an OTP, which should never be shared with another person.", "Uses a raw IP address instead of a recognizable organization domain."],
      explanation: "This message is very likely to be a scam. It pressures you to act quickly and asks for your OTP. Do not reply, share a code, or use the link. Contact the organization using its official app or a number you already trust.",
      ml_probability: 0.98, campaign_detected: true,
      technical_details: {
        parsed_host: "198.51.100.42", host_type: "ip_address", port: "Not specified",
        scheme: "http", https: "no", top_level_domain: "Not applicable (IP address)", url_length: 30, subdomain_count: 0,
        detected_url_indicators: ["The link does not use HTTPS.", "The link uses a raw IP address instead of a normal website name."],
        detected_message_indicators: ["The message asks for sensitive authentication or payment information."],
        triggered_rules: [
          { rule_id: "msg_sensitive_info", category: "message", score: 30, reason: "The message asks for sensitive authentication or payment information." },
          { rule_id: "url_raw_ip", category: "url", score: 30, reason: "The link uses a raw IP address instead of a normal website name." },
          { rule_id: "url_no_https", category: "url", score: 15, reason: "The link does not use HTTPS." },
        ],
      },
    },
  },
  hi: {
    low: {
      scan_reference: "261127000101", risk_score: 0, risk_level: "Low Risk", content_type: "url",
      reasons: ["टेक्स्ट में कोई सामान्य फ़िशिंग संकेत नहीं मिला, लेकिन यह लिंक असत्यापित है और सुरक्षित होने की गारंटी नहीं है।"],
      explanation: "कम जोखिम (असत्यापित) का मतलब केवल यह है कि इस टेक्स्ट-आधारित जाँच में कोई बड़ा चेतावनी संकेत नहीं मिला। यह साबित नहीं करता कि वेबसाइट या संदेश असली है—महत्वपूर्ण मामलों की पुष्टि आधिकारिक ऐप या बुकमार्क की गई वेबसाइट से ही करें।",
      ml_probability: 0.08, campaign_detected: false,
      technical_details: {
        parsed_host: "www.example.com", host_type: "domain", port: "Not specified",
        scheme: "https", https: "yes", top_level_domain: ".com", url_length: 23, subdomain_count: 1,
        detected_url_indicators: [], detected_message_indicators: [], triggered_rules: [],
      },
    },
    suspicious: {
      scan_reference: "261127000102", risk_score: 46, risk_level: "Suspicious", content_type: "url",
      reasons: ["डोमेन में किसी जाने-पहचाने ब्रांड जैसा नाम और एक असामान्य अतिरिक्त शब्द है।", "URL में साइन-इन पेज जैसा रास्ता है जिसका उपयोग लॉगिन जानकारी चुराने के लिए हो सकता है।"],
      explanation: "इस लिंक में कुछ चेतावनी के संकेत हैं। पता किसी जानी-मानी सेवा जैसा दिखता है, लेकिन यह उसका आधिकारिक डोमेन नहीं है। पासवर्ड या भुगतान जानकारी दर्ज न करें।",
      ml_probability: 0.71, campaign_detected: false,
      technical_details: {
        parsed_host: "paypal-verify.example", host_type: "domain", port: "Not specified",
        scheme: "https", https: "yes", top_level_domain: ".example", url_length: 43, subdomain_count: 0,
        detected_url_indicators: ["अनधिकृत वेब पते में एक प्रसिद्ध ब्रांड ('paypal') का नाम शामिल है।"],
        detected_message_indicators: [],
        triggered_rules: [{ rule_id: "url_brand_impersonation", category: "url", score: 30, reason: "Unrecognized domain containing brand 'paypal'." }],
      },
    },
    dangerous: {
      scan_reference: "261127000103", risk_score: 94, risk_level: "Dangerous", content_type: "message",
      reasons: ["KYC बंद होने की धमकी देकर जल्दबाज़ी का दबाव बनाता है।", "OTP माँगता है, जिसे कभी किसी के साथ साझा नहीं करना चाहिए।", "आधिकारिक वेबसाइट के बजाय सीधे IP नंबर का उपयोग करता है।"],
      explanation: "यह संदेश धोखाधड़ी (स्कैम) होने की पूरी संभावना है। यह तुरंत कार्रवाई करने का दबाव डालता है और OTP माँगता है। जवाब न दें, कोड साझा न करें और लिंक न खोलें। सीधे आधिकारिक ऐप या भरोसेमंद नंबर से संपर्क करें।",
      ml_probability: 0.98, campaign_detected: true,
      technical_details: {
        parsed_host: "198.51.100.42", host_type: "ip_address", port: "Not specified",
        scheme: "http", https: "no", top_level_domain: "Not applicable (IP address)", url_length: 30, subdomain_count: 0,
        detected_url_indicators: ["लिंक HTTPS का उपयोग नहीं करता।", "सीधे IP पते का उपयोग करता है।"],
        detected_message_indicators: ["OTP या संवेदनशील जानकारी माँगता है।"],
        triggered_rules: [
          { rule_id: "msg_sensitive_info", category: "message", score: 30, reason: "Sensitive authentication info requested." },
          { rule_id: "url_raw_ip", category: "url", score: 30, reason: "Raw IP address in URL." },
          { rule_id: "url_no_https", category: "url", score: 15, reason: "Non-HTTPS scheme." },
        ],
      },
    },
  },
};

const COPY = {
  en: {
    tagline: "CHECK BEFORE YOU CLICK.",
    privateBadge: "Private by design",
    eyebrow: "A calmer way to check suspicious messages",
    heroTitleTop: "Check before",
    heroTitleAccent: "you click.",
    heroDesc: "Suspicious link? Unexpected message? Check it before you trust it.",
    trust: [
      { title: "Zero-Click Text Analysis", sub: "URLs never opened" },
      { title: "English & हिन्दी Explanations", sub: "Clear plain language" },
      { title: "No Raw IPs Stored", sub: "Salted privacy logs" },
    ],
    floatTop: "Text only. No link visits.",
    floatBottom: "Signals, made simple",
    problemEyebrow: "THE PROBLEM WE'RE SOLVING",
    problemTitleTop: "Scams are getting more convincing.",
    problemTitleAccent: "Knowing what to trust shouldn't be hard.",
    problemDesc: "Modern scams hide behind lookalike letters (sЬi vs sbi), fake UPI cashback links, spoofed .eml email headers, and QR traps. PhishShield inspects text, voice dictation, QR images, and email headers offline—turning panic into clear 1930-ready action.",
    threats: [
      { title: "Digital Arrest, Voice Calls & Spoofed Emails", desc: "Fake CBI/TRAI threats, screen-sharing traps (AnyDesk), and spoofed .eml headers failing SPF/DKIM/DMARC—checkable by paste, upload, or voice." },
      { title: "Homograph Links, UPI Collect & QR Traps", desc: "Disguised Cyrillic/Punycode (xn--) URLs, zero-width characters, and upi://pay cashback tricks decoded offline before you ever tap or scan." },
      { title: "Malicious .APK, Challans & Panic Pressure", desc: "Fake RTO e-challan or electricity .apk downloads—flagged with X-ray phrase highlights, de-fanged safe links, and 1930 recovery steps." },
    ],
    howEyebrow: "SIMPLE BY DESIGN",
    howTitle: "A safer pause in four steps.",
    howDesc: "No technical knowledge needed. Just paste the text and understand the signals.",
    steps: [
      { title: "Paste", desc: "Copy in a suspicious link, SMS, or chat message." },
      { title: "Analyze", desc: "PhishShield checks the submitted text for warning signs." },
      { title: "Understand", desc: "Get a clear risk level and plain-language explanation." },
      { title: "Choose carefully", desc: "Use the evidence to decide your next step—without rushing." },
    ],
    guideEyebrow: "READ THE RESULT",
    guideTitle: "Three levels. One clearer decision.",
    guideDesc: "Risk scores are guidance based on signals found in the submitted text—not a guarantee about what will happen if you visit a link.",
    guideTiers: [
      { range: "00—24", label: "Low Risk (Unverified)", desc: "No strong warning signs found. The link is still unverified, not guaranteed safe." },
      { range: "25—59", label: "Suspicious", desc: "Some signals deserve caution. Pause and verify through an official channel." },
      { range: "60—100", label: "Dangerous", desc: "Strong scam indicators detected. Do not share details or engage with the message." },
    ],
    privacyEyebrow: "BUILT AROUND TRUST",
    privacyTitle: "Your caution deserves privacy.",
    privacyDesc: "PhishShield analyzes what you paste as text. It does not open, fetch, preview, or execute submitted links. The goal is to help people understand suspicious messages without putting them at greater risk.",
    privacyPoints: ["✓ Zero-click text analysis", "✓ English & हिन्दी explanations", "✓ No raw IPs stored in privacy logs"],
    faqEyebrow: "GOOD TO KNOW",
    faqTitle: "A few things you might be wondering.",
    faqs: [
      { q: "Does PhishShield open the link?", a: "No. Submitted URLs are treated as text only. The checker looks at the text and never visits the destination." },
      { q: "Does 'Low Risk' or 0/100 prove a site is authentic?", a: "No. PhishShield cannot prove authenticity from text alone. Low Risk (Unverified) or 0/100 only means no common phishing indicators were detected—verify important requests through the organisation's official app or bookmarked website." },
      { q: "Can it check messages as well as URLs?", a: "Yes. You can paste SMS, WhatsApp alerts, Digital Arrest/CBI threats, UPI/QR refund messages, e-challan .apk links, KYC notices, and job offers." },
      { q: "Who is PhishShield for?", a: "It is designed to make scam-warning signals easier to understand for students, parents, and families." },
    ],
    yourCheck: "YOUR CHECK",
    checkHeading: "What looks suspicious?",
    placeholder: "Paste a URL, SMS, Digital Arrest threat, UPI/QR request, e-challan .apk, KYC alert…",
    textOnlyNote: "Your text is analyzed as text only",
    clearBtn: "Clear",
    checkingBtn: "Checking text…",
    checkBtn: "Check safely",
    neverVisit: "We never visit submitted links",
    demoTitle: "TRY A SAFE DEMO INPUT",
    demoSub: "prefills text only, never opens links",
    demoLabels: {
      low: "Low-risk URL",
      kyc: "KYC + OTP (Raw IP)",
      brand: "Brand look-alike",
      short: "Shortened link",
      digital_arrest: "Digital Arrest / CBI",
      trai_sim: "TRAI SIM Cut",
      electricity_apk: "Electricity + .APK",
      remote_access: "AnyDesk Screen Share",
      homograph_sbi: "Homograph / Punycode",
      zero_width: "Zero-Width Chars",
      upi_cashback: "UPI Cashback Trap",
      email_spoof: "Email Spoof (.eml)",
    },
    rememberLabel: "Remember:",
    rememberTextPre: "'Low Risk' means no strong warning signs were found. It is ",
    rememberNot: "not",
    rememberTextPost: " a guarantee that a link is safe.",
    yourResult: "YOUR RESULT",
    resultHeading: "Clarity, not jargon.",
    liveCheck: "LIVE CHECK",
    samplePreview: "SAMPLE PREVIEW",
    rateAlertTitle: "A little pause",
    offlineAlertTitle: "Checker unavailable",
    rateError: "We've reached the scan limit for now. Please wait a moment and try again.",
    offlineError: "We can't reach the PhishShield checker right now. Check that the local API is running, then try again. Your text has not been checked.",
    copyError: "Copy wasn't available in this browser. You can select the reference and copy it manually.",
    riskOverview: "RISK OVERVIEW",
    riskScoreLabel: "risk score",
    typeUrl: "URL",
    typeMsg: "MESSAGE",
    tierLabels: { low: "Low Risk (Unverified)", suspicious: "Suspicious", dangerous: "Dangerous" },
    verdictHeadlines: { low: "No strong red flags found.", suspicious: "Take a closer look.", dangerous: "Do not engage with this." },
    verdictSubs: { low: "Low Risk (Unverified) does not prove authenticity or safety.", suspicious: "Some details deserve caution.", dangerous: "This has multiple high-risk signals." },
    unverifiedNote: "0/100 means no common phishing indicators were detected by this text-only scan. New or highly convincing scams may not show visible warning signs. Verify important requests through the organisation’s official app, bookmarked website, or a known contact method.",
    techDetailsTitle: "Technical details",
    techDetailsSub: "Extracted strictly from the pasted text — zero network or DNS lookups.",
    plainLangLabel: "IN PLAIN LANGUAGE",
    campaignBadge: "Repeated scam/campaign pattern detected",
    noticedHeading: "What we noticed",
    indicatorsWord: "indicators",
    emptyEvidence: "No specific indicators were returned for this check.",
    mlSignalLabel: "ML confidence signal",
    mlSignalNote: "Phishing similarity — supporting evidence only, not a verdict by itself.",
    scanRefLabel: "SCAN REFERENCE",
    copyRef: "Copy ref",
    copiedRef: "Copied",
    previewCaption: "Illustrative sample result · Not an actual scan",
    emptyTitle: "Your result will appear here.",
    emptyDescPre: "Paste a message or link on the left, then choose ",
    emptyDescBold: "Check safely",
    emptyDescPost: ". No link is opened.",
    emptyFoot: "Your check stays in this tab",
    previewResult: "PREVIEW A RESULT",
    previewLow: "Low risk",
    previewSuspicious: "Suspicious",
    previewDangerous: "Dangerous",
    previewRate: "429 limit",
    recentTitle: "Recent checks",
    recentSub: "THIS TAB ONLY · LAST 4",
    recentEmpty: "Your completed checks will show up here. They're kept only in this tab.",
    footerDesc: "Helping students, parents & families pause before they trust.",
    themeLight: "Light",
    themeDark: "Dark",
    quickCheckTab: "Quick Check",
    quickCheckTitle: "Quick Message & Link Check",
    quickCheckSub: "Test any URL or message without scrolling down.",
    viewFullResult: "View full breakdown & Technical details",
    scanQrBtn: "Scan QR image",
    qrNoSupport: "Your browser does not support offline QR image decoding. Please paste the QR link or text directly.",
    qrNotFound: "No QR code was detected in that image. Try a clearer screenshot or paste the text directly.",
    highlightsTitle: "Detected triggers in your text",
    playbookTitle: "What to do next",
    copyDefanged: "Copy de-fanged",
    copiedDefanged: "Copied safe",
    voiceBtn: "Voice",
    voiceListening: "Listening…",
    voiceNoSupport: "Voice input is not supported in this browser. Try Chrome or Edge, or paste the text directly.",
    emlBtn: "Upload .eml",
    emlError: "Could not read that email file. Please upload a .eml or .txt file.",
    shareWarning: "Share warning",
    sharedWarning: "Warning copied",
    downloadCard: "Safety Card PNG",
    simTitle: "Attack Simulator (Judge Presets)",
    simSub: "1-click realistic scam scenarios",
    arsenalEyebrow: "WHAT'S NEW · ZERO-CLICK DEFENSE ARSENAL",
    arsenalTitleTop: "Upgraded for modern scams.",
    arsenalTitleAccent: "Every layer stays offline-safe.",
    arsenalDesc: "From Cyrillic lookalike links and UPI collect traps to voice dictation and PNG warning cards—explore everything new inside PhishShield.",
    arsenalFilters: [
      { id: "all", label: "All Features (12)" },
      { id: "detect", label: "Detect" },
      { id: "inspect", label: "Inspect" },
      { id: "respond", label: "Respond & Share" },
    ],
    arsenalTryBtn: "Try demo →",
    arsenalCards: [
      {
        id: "zero_click", cat: "detect", badge: "Zero-Click Engine",
        title: "URL, SMS & Digital Arrest Scanner",
        desc: "Detects raw IPs, brand spoofing, shorteners, .apk e-challans, AnyDesk traps & CBI/TRAI threats without opening links.",
        scenarioId: "kyc",
      },
      {
        id: "homograph", cat: "detect", badge: "sЬi vs sbi · xn--",
        title: "Homograph & Punycode X-Ray",
        desc: "Catches disguised Cyrillic/Greek lookalike domains, xn-- Punycode, and invisible zero-width characters.",
        scenarioId: "homograph_sbi",
      },
      {
        id: "upi", cat: "inspect", badge: "upi://pay",
        title: "UPI Intent Deep-Inspector",
        desc: "Parses payee VPA, name, amount & note offline to expose cashback/refund traps before you open any payment app.",
        scenarioId: "upi_cashback",
      },
      {
        id: "eml", cat: "inspect", badge: "SPF · DKIM · DMARC",
        title: "Offline .eml Header Spoof Lab",
        desc: "Drop any .eml file or paste email headers to spot From vs Reply-To mismatches and failed SPF/DMARC checks.",
        scenarioId: "email_spoof",
      },
      {
        id: "qr", cat: "inspect", badge: "Zero-Upload QR",
        title: "Browser-Only QR Image Scanner",
        desc: "Decodes QR screenshots locally in your browser using BarcodeDetector—zero images ever leave your device.",
        action: "qr",
      },
      {
        id: "voice", cat: "detect", badge: "en-IN · hi-IN",
        title: "Voice-to-Text Scam Check",
        desc: "Dictate suspicious phone-call scripts in English or Hindi—designed so parents and elders never have to type.",
        action: "voice",
      },
      {
        id: "highlight", cat: "detect", badge: "X-Ray Highlights",
        title: "Suspicious Phrase Highlighter",
        desc: "Highlights the exact trigger words (OTP, digital arrest, .apk, raw IP) right inside your pasted message.",
        scenarioId: "digital_arrest",
      },
      {
        id: "playbook", cat: "respond", badge: "1930 · cybercrime.gov.in",
        title: "1930 Recovery Playbook",
        desc: "Gives threat-specific action steps—from Airplane Mode for .apk spyware to India's 1930 cyber fraud helpline.",
        scenarioId: "electricity_apk",
      },
      {
        id: "card", cat: "respond", badge: "hxxp:// · PNG Card",
        title: "De-Fanged Link & Safety Card PNG",
        desc: "Copy neutralized links (hxxp://198[.]51...) or export a local PNG warning card for family WhatsApp groups.",
        scenarioId: "trai_sim",
      },
      {
        id: "sidebar", cat: "inspect", badge: "Quick Check Drawer",
        title: "Persistent Quick-Test Sidebar",
        desc: "Test any URL, message, QR, voice, or .eml from anywhere on the page without scrolling down.",
        action: "sidebar",
      },
      {
        id: "bilingual", cat: "respond", badge: "EN / हिन्दी · Privacy",
        title: "Bilingual & Salted Privacy Logs",
        desc: "Plain-language explanations in English & Hindi, Dark/Light themes, and zero raw IPs stored.",
      },
      {
        id: "ext", cat: "respond", badge: "Chrome Guard",
        title: "Live Hover & Paste Guard",
        desc: "Chrome extension flags deceptive anchor text vs href mismatches on hover and warns when risky text is pasted.",
      },
    ],
  },
  hi: {
    tagline: "क्लिक करने से पहले जाँचें।",
    privateBadge: "गोपनीयता-प्रथम डिज़ाइन",
    eyebrow: "संदिग्ध संदेश जाँचने का शांत और सुरक्षित तरीका",
    heroTitleTop: "क्लिक करने से पहले,",
    heroTitleAccent: "एक बार जाँच लें।",
    heroDesc: "संदिग्ध लिंक या संदेश का टेक्स्ट यहाँ पेस्ट करें। हम लिंक खोले बिना उसके खतरे के संकेत दिखाते हैं।",
    trust: [
      { title: "ज़ीरो-क्लिक टेक्स्ट जाँच", sub: "कोई लिंक नहीं खुलता" },
      { title: "English व हिन्दी व्याख्या", sub: "सरल भाषा में समझ" },
      { title: "कोई IP सेव नहीं", sub: "सुरक्षित गोपनीय लॉग" },
    ],
    floatTop: "सिर्फ़ टेक्स्ट। कोई लिंक नहीं खुलता।",
    floatBottom: "संकेत, आसान भाषा में",
    problemEyebrow: "हम किस समस्या को हल कर रहे हैं",
    problemTitleTop: "ऑनलाइन ठगी लगातार बढ़ रही है।",
    problemTitleAccent: "क्या सही है यह समझना कठिन नहीं होना चाहिए।",
    problemDesc: "आज की ठगी नकली अक्षर वाले लिंक (sЬi बनाम sbi), फर्जी UPI कैशबैक, नकली .eml ईमेल हेडर और QR जाल में छिपी होती है। PhishShield टेक्स्ट, वॉइस, QR और ईमेल हेडर को बिना लिंक खोले जाँचता है और 1930 सुरक्षा कदम दिखाता है।",
    threats: [
      { title: "डिजिटल अरेस्ट, कॉल व नकली ईमेल (.eml)", desc: "नकली CBI/TRAI धमकी, स्क्रीन-शेयरिंग (AnyDesk) और SPF/DKIM/DMARC फेल होने वाले स्पूफ ईमेल—टेक्स्ट, फ़ाइल या बोलकर जाँचें।" },
      { title: "होमोग्राफ लिंक, UPI व QR जाल", desc: "असली जैसे दिखने वाले (xn--) डोमेन, छिपे zero-width अक्षर और upi://pay कैशबैक ठगी की ऑफ़लाइन जाँच।" },
      { title: "खतरनाक .APK, ई-चालान व हाइलाइट बचाव", desc: "नकली बिजली बिल या चालान .apk डाउनलोड—संदिग्ध शब्द हाइलाइटर, सुरक्षित कॉपी और 1930 हेल्पलाइन निर्देश के साथ।" },
    ],
    howEyebrow: "सरल और सुरक्षित प्रक्रिया",
    howTitle: "चार आसान चरणों में सुरक्षित जाँच।",
    howDesc: "किसी तकनीकी ज्ञान की ज़रूरत नहीं। बस टेक्स्ट पेस्ट करें और संकेत समझें।",
    steps: [
      { title: "पेस्ट करें", desc: "संदिग्ध लिंक, SMS या चैट संदेश यहाँ डालें।" },
      { title: "विश्लेषण", desc: "PhishShield बिना लिंक खोले टेक्स्ट में खतरे के संकेत खोजता है।" },
      { title: "समझें", desc: "स्पष्ट जोखिम स्तर और आसान हिन्दी में व्याख्या पाएं।" },
      { title: "सोचकर निर्णय लें", desc: "जल्दबाज़ी किए बिना सबूत के आधार पर अगला कदम तय करें।" },
    ],
    guideEyebrow: "परिणाम को समझें",
    guideTitle: "तीन स्तर। एक स्पष्ट निर्णय।",
    guideDesc: "जोखिम स्कोर टेक्स्ट में मिले संकेतों पर आधारित मार्गदर्शन है—यह किसी लिंक की 100% सुरक्षा की गारंटी नहीं है।",
    guideTiers: [
      { range: "00—24", label: "कम जोखिम (असत्यापित)", desc: "बड़े खतरे के संकेत नहीं मिले। फिर भी लिंक असत्यापित है, पूरी तरह सुरक्षित नहीं माना जा सकता।" },
      { range: "25—59", label: "संदिग्ध (Suspicious)", desc: "कुछ संकेत सावधानी बरतने को कहते हैं। रुकें और आधिकारिक ऐप या वेबसाइट से पुष्टि करें।" },
      { range: "60—100", label: "खतरनाक (Dangerous)", desc: "ठगी के मज़बूत संकेत मिले हैं। कोई जानकारी साझा न करें और लिंक न खोलें।" },
    ],
    privacyEyebrow: "भरोसे पर आधारित",
    privacyTitle: "आपकी सावधानी गोपनीय रहनी चाहिए।",
    privacyDesc: "PhishShield आपके पेस्ट किए गए टेक्स्ट की ही जाँच करता है। यह किसी भी लिंक को खोलता, डाउनलोड या चलाता नहीं है—ताकि जाँच करते समय भी आप सुरक्षित रहें।",
    privacyPoints: ["✓ ज़ीरो-क्लिक टेक्स्ट जाँच", "✓ English और हिन्दी में व्याख्या", "✓ गोपनीयता लॉग में असली IP स्टोर नहीं"],
    faqEyebrow: "अक्सर पूछे जाने वाले सवाल",
    faqTitle: "कुछ बातें जो आप जानना चाहेंगे।",
    faqs: [
      { q: "क्या PhishShield लिंक को खोलता है?", a: "नहीं। डाले गए URL को केवल टेक्स्ट के रूप में देखा जाता है; जाँच के दौरान वेबसाइट कभी नहीं खोली जाती।" },
      { q: "क्या 'कम जोखिम' या 0/100 का मतलब असली या सुरक्षित है?", a: "नहीं। PhishShield केवल टेक्स्ट से किसी वेबसाइट के असली होने की पुष्टि नहीं कर सकता। इसका मतलब केवल इतना है कि कोई आम ठगी का संकेत नहीं मिला—आधिकारिक ऐप या बुकमार्क की गई वेबसाइट से ही पुष्टि करें।" },
      { q: "क्या यह URL के अलावा पूरे संदेश भी जाँच सकता है?", a: "हाँ। आप SMS, WhatsApp संदेश, डिजिटल अरेस्ट/CBI धमकी, UPI/QR रिफंड, ई-चालान .apk लिंक, KYC नोटिस या नौकरी के ऑफर पेस्ट कर सकते हैं।" },
      { q: "PhishShield किसके लिए बनाया गया है?", a: "यह छात्रों, माता-पिता और परिवारों के लिए बनाया गया है ताकि ठगी के संकेत आसानी से समझ आ सकें।" },
    ],
    yourCheck: "आपकी जाँच",
    checkHeading: "क्या संदिग्ध लग रहा है?",
    placeholder: "कोई URL, SMS, डिजिटल अरेस्ट धमकी, UPI/QR संदेश, ई-चालान .apk या KYC अलर्ट पेस्ट करें…",
    textOnlyNote: "आपका टेक्स्ट केवल टेक्स्ट के रूप में जाँचा जाता है",
    clearBtn: "साफ़ करें",
    checkingBtn: "जाँच हो रही है…",
    checkBtn: "सुरक्षित जाँचें",
    neverVisit: "हम डाले गए लिंक कभी नहीं खोलते",
    demoTitle: "सुरक्षित उदाहरण आज़माएं",
    demoSub: "केवल टेक्स्ट भरता है, लिंक नहीं खोलता",
    demoLabels: {
      low: "कम जोखिम URL",
      kyc: "KYC + OTP (सीधा IP)",
      brand: "नकली ब्रांड लिंक",
      short: "छोटा किया लिंक",
      digital_arrest: "डिजिटल अरेस्ट / CBI",
      trai_sim: "TRAI सिम कटौती",
      electricity_apk: "बिजली बिल + .APK",
      remote_access: "AnyDesk स्क्रीन शेयर",
      homograph_sbi: "होमोग्राफ / Punycode",
      zero_width: "छिपे Zero-Width अक्षर",
      upi_cashback: "UPI कैशबैक जाल",
      email_spoof: "ईमेल स्पूफ (.eml)",
    },
    rememberLabel: "याद रखें:",
    rememberTextPre: "'कम जोखिम' का अर्थ है कि बड़े खतरे के संकेत नहीं मिले। यह लिंक के सुरक्षित होने की गारंटी ",
    rememberNot: "नहीं",
    rememberTextPost: " है।",
    yourResult: "आपका परिणाम",
    resultHeading: "सरल और साफ़ जानकारी।",
    liveCheck: "लाइव जाँच",
    samplePreview: "उदाहरण पूर्वावलोकन",
    rateAlertTitle: "थोड़ा रुकें",
    offlineAlertTitle: "जाँच सेवा उपलब्ध नहीं",
    rateError: "अभी के लिए जाँच की सीमा पूरी हो गई है। कृपया एक मिनट रुककर फिर प्रयास करें।",
    offlineError: "अभी PhishShield जाँच सेवा से संपर्क नहीं हो पा रहा है। सुनिश्चित करें कि लोकल API चल रहा है। आपका टेक्स्ट अभी जाँचा नहीं गया है।",
    copyError: "इस ब्राउज़र में कॉपी उपलब्ध नहीं है। आप संदर्भ संख्या मैन्युअल रूप से कॉपी कर सकते हैं।",
    riskOverview: "जोखिम सारांश",
    riskScoreLabel: "जोखिम स्कोर",
    typeUrl: "URL",
    typeMsg: "संदेश",
    tierLabels: { low: "कम जोखिम (असत्यापित)", suspicious: "संदिग्ध (Suspicious)", dangerous: "खतरनाक (Dangerous)" },
    verdictHeadlines: { low: "कोई बड़ा ख़तरा नहीं मिला।", suspicious: "थोड़ी सावधानी ज़रूरी है।", dangerous: "इस संदेश पर भरोसा न करें।" },
    verdictSubs: { low: "कम जोखिम (असत्यापित) होने का मतलब असली या सुरक्षित होना नहीं है।", suspicious: "कुछ संकेत संदिग्ध हैं—आधिकारिक स्रोत से जांचें।", dangerous: "इसमें कई गंभीर ठगी के संकेत मिले हैं।" },
    unverifiedNote: "0/100 का मतलब है कि इस टेक्स्ट-आधारित जाँच में कोई सामान्य फ़िशिंग संकेत नहीं मिला। नए या बेहद चालाक स्कैम में दिखने वाले संकेत न भी हों। महत्वपूर्ण अनुरोधों की पुष्टि आधिकारिक ऐप, बुकमार्क की गई वेबसाइट या ज्ञात नंबर से करें।",
    techDetailsTitle: "Technical details",
    techDetailsSub: "केवल पेस्ट किए गए टेक्स्ट से निकाले गए तथ्य — कोई नेटवर्क या DNS जाँच नहीं।",
    plainLangLabel: "सरल भाषा में",
    campaignBadge: "बार-बार दोहराया जाने वाला स्कैम पैटर्न मिला",
    noticedHeading: "हमने क्या देखा",
    indicatorsWord: "संकेत",
    emptyEvidence: "इस जाँच में कोई विशेष संकेत नहीं मिला।",
    mlSignalLabel: "ML मॉडल संकेत",
    mlSignalNote: "फ़िशिंग समानता — केवल सहायक संकेत, अकेले अंतिम निर्णय नहीं।",
    scanRefLabel: "स्कैन संदर्भ संख्या",
    copyRef: "कॉपी करें",
    copiedRef: "कॉपी हो गया",
    previewCaption: "उदाहरण परिणाम · वास्तविक जाँच नहीं",
    emptyTitle: "आपका परिणाम यहाँ दिखेगा।",
    emptyDescPre: "बाईं ओर कोई संदेश या लिंक पेस्ट करें और ",
    emptyDescBold: "सुरक्षित जाँचें",
    emptyDescPost: " दबाएं। कोई लिंक नहीं खुलेगा।",
    emptyFoot: "आपकी जाँच इसी टैब में रहती है",
    previewResult: "परिणाम का उदाहरण देखें",
    previewLow: "कम जोखिम",
    previewSuspicious: "संदिग्ध",
    previewDangerous: "खतरनाक",
    previewRate: "429 सीमा",
    recentTitle: "हाल की जाँचें",
    recentSub: "केवल इसी टैब में · अंतिम 4",
    recentEmpty: "आपकी पूरी हुई जाँचें यहाँ दिखेंगी। यह केवल इसी टैब में रहती हैं।",
    footerDesc: "छात्रों, माता-पिता और परिवारों को क्लिक करने से पहले रुककर सोचने में मदद।",
    themeLight: "लाइट",
    themeDark: "डार्क",
    quickCheckTab: "त्वरित जाँच",
    quickCheckTitle: "त्वरित संदेश व लिंक जाँच",
    quickCheckSub: "नीचे स्क्रॉल किए बिना यहीं से संदेश या लिंक जाँचें।",
    viewFullResult: "पूरा विवरण व Technical details देखें",
    scanQrBtn: "QR इमेज जाँचें",
    qrNoSupport: "आपका ब्राउज़र ऑफ़लाइन QR डिकोडिंग सपोर्ट नहीं करता। कृपया QR का लिंक या टेक्स्ट सीधे पेस्ट करें।",
    qrNotFound: "इस इमेज में कोई QR कोड नहीं मिला। साफ़ स्क्रीनशॉट आज़माएं या टेक्स्ट सीधे पेस्ट करें।",
    highlightsTitle: "टेक्स्ट में मिले संदिग्ध शब्द",
    playbookTitle: "आगे क्या करें (सुरक्षा कदम)",
    copyDefanged: "सुरक्षित कॉपी",
    copiedDefanged: "कॉपी हो गया",
    voiceBtn: "बोलकर लिखें",
    voiceListening: "सुन रहा है…",
    voiceNoSupport: "इस ब्राउज़र में वॉइस इनपुट उपलब्ध नहीं है। कृपया Chrome/Edge आज़माएं या टेक्स्ट पेस्ट करें।",
    emlBtn: ".eml फ़ाइल",
    emlError: "ईमेल फ़ाइल पढ़ी नहीं जा सकी। कृपया .eml या .txt फ़ाइल चुनें।",
    shareWarning: "चेतावनी साझा करें",
    sharedWarning: "चेतावनी कॉपी हुई",
    downloadCard: "सुरक्षा कार्ड PNG",
    simTitle: "हमला सिम्युलेटर (डेमो)",
    simSub: "1-क्लिक असली जैसे स्कैम उदाहरण",
    arsenalEyebrow: "नया अपडेट · ज़ीरो-क्लिक सुरक्षा कवच",
    arsenalTitleTop: "आधुनिक ठगी के लिए तैयार।",
    arsenalTitleAccent: "हर जाँच पूरी तरह सुरक्षित।",
    arsenalDesc: "नकली अक्षर वाले लिंक और UPI जाल से लेकर वॉइस डिक्टेशन और PNG चेतावनी कार्ड तक—जानें PhishShield में क्या नया जुड़ा है।",
    arsenalFilters: [
      { id: "all", label: "सभी फीचर्स (12)" },
      { id: "detect", label: "पहचान" },
      { id: "inspect", label: "गहन जाँच" },
      { id: "respond", label: "बचाव व साझा" },
    ],
    arsenalTryBtn: "डेमो आज़माएं →",
    arsenalCards: [
      {
        id: "zero_click", cat: "detect", badge: "ज़ीरो-क्लिक इंजन",
        title: "URL, SMS व डिजिटल अरेस्ट स्कैनर",
        desc: "बिना लिंक खोले कच्चे IP, नकली ब्रांड, शॉर्टनर, .apk ई-चालान, AnyDesk व CBI/TRAI धमकियों को पकड़ता है।",
        scenarioId: "kyc",
      },
      {
        id: "homograph", cat: "detect", badge: "sЬi बनाम sbi · xn--",
        title: "होमोग्राफ व Punycode एक्स-रे",
        desc: "असली जैसे दिखने वाले गैर-अंग्रेज़ी अक्षर, xn-- डोमेन और छिपे हुए zero-width अक्षरों को तुरंत पकड़ता है।",
        scenarioId: "homograph_sbi",
      },
      {
        id: "upi", cat: "inspect", badge: "upi://pay",
        title: "UPI इंटेंट डीप-इंस्पेक्टर",
        desc: "ऑफ़लाइन ही VPA, नाम, राशि और नोट पढ़कर 'कैशबैक/रिफंड के लिए PIN डालें' जैसी ठगी पकड़ता है।",
        scenarioId: "upi_cashback",
      },
      {
        id: "eml", cat: "inspect", badge: "SPF · DKIM · DMARC",
        title: "ऑफ़लाइन .eml ईमेल हेडर जाँच",
        desc: "कोई भी .eml फ़ाइल या ईमेल हेडर डालें और From बनाम Reply-To स्पूफिंग व SPF/DMARC विफलता देखें।",
        scenarioId: "email_spoof",
      },
      {
        id: "qr", cat: "inspect", badge: "ऑफ़लाइन QR",
        title: "ब्राउज़र-ओनली QR इमेज स्कैनर",
        desc: "बिना किसी सर्वर अपलोड के सीधे आपके ब्राउज़र में QR स्क्रीनशॉट की जाँच करता है।",
        action: "qr",
      },
      {
        id: "voice", cat: "detect", badge: "en-IN · hi-IN",
        title: "बोलकर स्कैम जाँच (Voice)",
        desc: "संदिग्ध कॉल की बात हिंदी या अंग्रेज़ी में बोलकर लिखें—माता-पिता और बुज़ुर्गों के लिए बेहद आसान।",
        action: "voice",
      },
      {
        id: "highlight", cat: "detect", badge: "हाइलाइटर",
        title: "संदिग्ध शब्द हाइलाइटर",
        desc: "आपके संदेश में मौजूद खतरनाक शब्दों (OTP, डिजिटल अरेस्ट, .apk) को सीधे रंगीन हाइलाइट करता है।",
        scenarioId: "digital_arrest",
      },
      {
        id: "playbook", cat: "respond", badge: "1930 · cybercrime.gov.in",
        title: "1930 बचाव व रिकवरी प्लेबुक",
        desc: ".apk के लिए Airplane Mode से लेकर भारत की 1930 साइबर हेल्पलाइन तक सटीक कदम बताता है।",
        scenarioId: "electricity_apk",
      },
      {
        id: "card", cat: "respond", badge: "hxxp:// · PNG कार्ड",
        title: "सुरक्षित कॉपी व PNG सुरक्षा कार्ड",
        desc: "लिंक को सुरक्षित रूप (hxxp://198[.]51...) में कॉपी करें या परिवार के WhatsApp ग्रुप के लिए PNG कार्ड डाउनलोड करें।",
        scenarioId: "trai_sim",
      },
      {
        id: "sidebar", cat: "inspect", badge: "त्वरित जाँच",
        title: "हमेशा तैयार क्विक-चेक साइडबार",
        desc: "नीचे स्क्रॉल किए बिना पेज पर कहीं से भी URL, संदेश, QR, वॉइस या .eml तुरंत जाँचें।",
        action: "sidebar",
      },
      {
        id: "bilingual", cat: "respond", badge: "EN / हिन्दी · गोपनीयता",
        title: "द्विभाषी व्याख्या व गोपनीय लॉग",
        desc: "English और हिन्दी में आसान व्याख्या, डार्क/लाइट थीम और कोई कच्चा IP सेव नहीं।",
      },
      {
        id: "ext", cat: "respond", badge: "Chrome सुरक्षा",
        title: "लाइव होवर और पेस्ट गार्ड",
        desc: "Chrome एक्सटेंशन माउस ले जाने पर नकली लिंक टेक्स्ट पकड़ता है और संदिग्ध पेस्ट पर तुरंत चेतावनी देता है।",
      },
    ],
  },
};

/* ── Inline SVG Icons ─────────────────────────────────────────────────────── */
function Icon({ name, size = 18 }) {
  const p = { width: size, height: size, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: 1.8, strokeLinecap: "round", strokeLinejoin: "round", "aria-hidden": true };
  const paths = {
    shield:  <><path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11Z"/><path d="m9 12 2 2 4-4"/></>,
    lock:    <><rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 1 1 8 0v3"/></>,
    copy:    <><rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3"/></>,
    arrow:   <><path d="M5 12h14"/><path d="m13 6 6 6-6 6"/></>,
    spark:   <><path d="m12 3 1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8L12 3Z"/><path d="m19 16 .8 2.2L22 19l-2.2.8L19 22l-.8-2.2L16 19l2.2-.8L19 16Z"/></>,
    clock:   <><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></>,
    alert:   <><path d="M12 3 2.8 20h18.4L12 3Z"/><path d="M12 9v4m0 3h.01"/></>,
    close:   <><path d="m18 6-12 12M6 6l12 12"/></>,
    eye:     <><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7Z"/><circle cx="12" cy="12" r="3"/></>,
    check:   <><polyline points="20 6 9 17 4 12"/></>,
    mic:     <><rect x="9" y="2" width="6" height="12" rx="3"/><path d="M5 10a7 7 0 0 0 14 0M12 17v4M8 21h8"/></>,
    file:    <><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></>,
    share:   <><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></>,
  };
  return <svg {...p}>{paths[name] || paths.shield}</svg>;
}

/* ── Shield Logo SVG ──────────────────────────────────────────────────────── */
function ShieldLogo({ size = 36 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 36 36" fill="none" aria-hidden="true">
      <defs>
        <linearGradient id="sg" x1="0" y1="0" x2="36" y2="36" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#18D9D2"/>
          <stop offset="100%" stopColor="#A855F7"/>
        </linearGradient>
        <linearGradient id="sg2" x1="0" y1="0" x2="36" y2="36" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#18D9D2" stopOpacity="0.18"/>
          <stop offset="100%" stopColor="#A855F7" stopOpacity="0.10"/>
        </linearGradient>
      </defs>
      <path d="M18 2 32 8v10c0 9-6.3 15.3-14 18C10.3 33.3 4 27 4 18V8L18 2Z" fill="url(#sg2)" stroke="url(#sg)" strokeWidth="1.5"/>
      <path d="m12 18 4 4 8-8" stroke="url(#sg)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
    </svg>
  );
}

/* ── Hero Shield Illustration ─────────────────────────────────────────────── */
function HeroShield() {
  return (
    <svg width="160" height="176" viewBox="0 0 160 176" fill="none" aria-hidden="true">
      <defs>
        <linearGradient id="hg1" x1="0" y1="0" x2="160" y2="176" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#18D9D2" stopOpacity="0.22"/>
          <stop offset="100%" stopColor="#A855F7" stopOpacity="0.14"/>
        </linearGradient>
        <linearGradient id="hg2" x1="0" y1="0" x2="160" y2="176" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#18D9D2"/>
          <stop offset="60%" stopColor="#18D9D2"/>
          <stop offset="100%" stopColor="#A855F7"/>
        </linearGradient>
        <filter id="hglow" x="-40%" y="-40%" width="180%" height="180%">
          <feGaussianBlur stdDeviation="8" result="blur"/>
          <feComposite in="SourceGraphic" in2="blur" operator="over"/>
        </filter>
      </defs>
      {/* Outer glow ring */}
      <ellipse cx="80" cy="90" rx="68" ry="72" fill="none" stroke="#18D9D2" strokeWidth="1" strokeOpacity="0.12"/>
      <ellipse cx="80" cy="90" rx="52" ry="56" fill="none" stroke="#A855F7" strokeWidth="0.8" strokeOpacity="0.10"/>
      {/* Shield body */}
      <path d="M80 8 148 36v44c0 42-29.4 68.3-68 84C41.4 148.3 12 122 12 80V36L80 8Z" fill="url(#hg1)" stroke="url(#hg2)" strokeWidth="2"/>
      {/* Checkmark */}
      <path d="m54 92 18 18 34-34" stroke="url(#hg2)" strokeWidth="4.5" strokeLinecap="round" strokeLinejoin="round" filter="url(#hglow)"/>
    </svg>
  );
}

/* ── Risk Gauge ───────────────────────────────────────────────────────────── */
function RiskGauge({ score, tier, scoreLabel }) {
  const radius = 60;
  const circumference = 2 * Math.PI * radius;
  const progress = circumference * (score / 100);
  return (
    <div className={`risk-gauge ${tier.tone}`} role="img" aria-label={`Risk score ${score} out of 100`}>
      <svg viewBox="0 0 148 148" className="gauge-svg">
        <defs>
          <linearGradient id="gauge-track-g" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#18D9D2" stopOpacity="0.08"/>
            <stop offset="100%" stopColor="#A855F7" stopOpacity="0.06"/>
          </linearGradient>
        </defs>
        <circle className="gauge-track" cx="74" cy="74" r={radius}/>
        <circle className="gauge-progress" cx="74" cy="74" r={radius} strokeDasharray={`${progress} ${circumference}`}/>
      </svg>
      <div className="gauge-center">
        <strong>{score}<small>/100</small></strong>
        <span>{scoreLabel}</span>
      </div>
    </div>
  );
}

/* ── Utility ──────────────────────────────────────────────────────────────── */
function getTier(score, t) {
  if (score <= 24) return { key: "low",       label: t.tierLabels.low,       tone: "low" };
  if (score <= 59) return { key: "suspicious", label: t.tierLabels.suspicious, tone: "suspicious" };
  return               { key: "dangerous",   label: t.tierLabels.dangerous,  tone: "dangerous" };
}

function normalizeResult(data) {
  const score = Math.max(0, Math.min(100, Number(data?.risk_score) || 0));
  return {
    ...data,
    risk_score:    score,
    reasons:       Array.isArray(data?.reasons) ? data.reasons : [],
    matched_terms: Array.isArray(data?.matched_terms) ? data.matched_terms : [],
    explanation:   data?.explanation || "No plain-language explanation was provided.",
    scan_reference: String(data?.scan_reference || "Unavailable"),
    content_type:  data?.content_type || "message",
  };
}

function renderHighlightedText(text, terms) {
  if (!text || !Array.isArray(terms) || !terms.length) return text;
  const escaped = terms
    .filter(Boolean)
    .map(t => t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  if (!escaped.length) return text;
  const regex = new RegExp(`(${escaped.join("|")})`, "gi");
  const lowerSet = new Set(terms.map(t => t.toLowerCase()));
  return text.split(regex).map((part, idx) =>
    lowerSet.has(part.toLowerCase())
      ? <mark key={idx} className="trigger-highlight">{part}</mark>
      : <React.Fragment key={idx}>{part}</React.Fragment>
  );
}

function getPlaybookSteps(result, lang) {
  if (!result || result.risk_score < 25) return [];
  const ruleIds = new Set((result.technical_details?.triggered_rules || []).map(r => r.rule_id));
  const isHi = lang === "hi";
  const steps = [];
  if (ruleIds.has("msg_digital_arrest")) {
    steps.push(isHi
      ? "पुलिस, CBI या कस्टम कभी वीडियो कॉल पर 'डिजिटल अरेस्ट' या पैसे की माँग नहीं करते—तुरंत कॉल काटें।"
      : "Police, CBI, and customs never conduct 'digital arrests' or demand money over video calls—hang up immediately.");
  }
  if (ruleIds.has("msg_apk_challan") || ruleIds.has("url_executable_download") || ruleIds.has("msg_remote_access")) {
    steps.push(isHi
      ? "कोई .APK या रिमोट-एक्सेस ऐप (AnyDesk/TeamViewer) इंस्टॉल न करें। यदि पहले से इंस्टॉल है तो तुरंत Airplane Mode चालू करें और ऐप हटाएं।"
      : "Do not install any .APK or remote-access app (AnyDesk/TeamViewer). If already installed, turn on Airplane Mode immediately and uninstall it.");
  }
  if (ruleIds.has("msg_upi_qr") || ruleIds.has("msg_sensitive_info") || ruleIds.has("upi_collect_trap") || ruleIds.has("upi_vpa_mismatch")) {
    steps.push(isHi
      ? "पैसे पाने के लिए कभी UPI PIN या QR कोड स्कैन की ज़रूरत नहीं होती। यदि पैसे कट गए हैं तो तुरंत 1930 पर कॉल करें या cybercrime.gov.in पर रिपोर्ट करें।"
      : "You never need to enter a UPI PIN or scan a QR code to receive money. If money was debited, call 1930 immediately or report at cybercrime.gov.in.");
  }
  if (ruleIds.has("email_reply_to_mismatch") || ruleIds.has("email_return_path_mismatch") || ruleIds.has("email_auth_fail")) {
    steps.push(isHi
      ? "इस ईमेल का जवाब न दें और कोई अटैचमेंट न खोलें। सीधे बैंक या कंपनी की आधिकारिक वेबसाइट पर जाकर पुष्टि करें।"
      : "Do not reply to this email or open attachments. Verify directly via the organisation's official website or support portal.");
  }
  if (!steps.length) {
    steps.push(isHi
      ? "लिंक न खोलें और न ही OTP/पासवर्ड साझा करें। पुष्टि के लिए सीधे आधिकारिक ऐप या बुकमार्क की गई वेबसाइट का उपयोग करें।"
      : "Do not click links, reply, or share OTPs/passwords. Verify directly via the organisation's official app or bookmarked website.");
  }
  return steps;
}

/* ══════════════════════════════════════════════════════════════════════════ */
export default function PhishShield() {
  const [content,  setContent]  = useState("");
  const [language, setLanguage] = useState("en");
  const [theme,    setTheme]    = useState(() => {
    try { return window.localStorage.getItem("ps_theme") || "dark"; }
    catch { return "dark"; }
  });
  const [loading,  setLoading]  = useState(false);
  const [result,   setResult]   = useState(null);
  const [error,    setError]    = useState(null);
  const [recent,   setRecent]   = useState([]);
  const [preview,  setPreview]  = useState("dangerous");
  const [copied,   setCopied]   = useState(false);
  const [copiedDefanged, setCopiedDefanged] = useState(false);
  const [sharedWarning, setSharedWarning] = useState(false);
  const [listening, setListening] = useState(false);
  const [selectedDemo, setSelectedDemo] = useState(null);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [arsenalFilter, setArsenalFilter] = useState("all");
  const [scannedText, setScannedText] = useState("");
  const qrInputRef = useRef(null);
  const emlInputRef = useRef(null);
  const recognitionRef = useRef(null);

  useEffect(() => {
    document.body.dataset.theme = theme;
    try { window.localStorage.setItem("ps_theme", theme); }
    catch { /* ignore */ }
  }, [theme]);

  useEffect(() => {
    if (!API_URL || API_URL.includes("127.0.0.1") || API_URL.includes("localhost")) return;
    const base = String(API_URL).replace(/\/+$/, "");
    fetch(`${base}/health`, { method: "GET" }).catch(() => {});
  }, []);

  const t            = COPY[language]      || COPY.en;
  const mocks        = MOCKS_BY_LANG[language] || MOCKS_BY_LANG.en;
  const activeResult = result || (preview === "rate" ? null : mocks[preview]);
  const tier         = useMemo(() => (activeResult ? getTier(activeResult.risk_score, t) : null), [activeResult, t]);
  const isPreview    = !result && preview !== "rate";
  const playbookSteps = useMemo(() => getPlaybookSteps(activeResult, language), [activeResult, language]);

  function handleLanguageChange(nextLang) {
    setLanguage(nextLang);
    if (preview === "rate" && error?.type === "rate") {
      const nextCopy = COPY[nextLang] || COPY.en;
      setError({ type: "rate", message: nextCopy.rateError });
    }
  }

  function useDemo(demo) {
    setContent(demo.value);
    setSelectedDemo(demo.id);
    setError(null);
  }

  function showPreview(value) {
    setPreview(value);
    setResult(null);
    setError(value === "rate" ? { type: "rate", message: t.rateError } : null);
  }

  async function runScanText(rawText) {
    const trimmed = String(rawText || "").trim();
    if (trimmed.length < 3 || loading) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      // Submitted text is sent only to the configured analysis API. This app never
      // opens, fetches, previews, or executes a URL found in the submitted content.
      const data = normalizeResult(await submitScan({ content: trimmed, language, apiUrl: API_URL }));
      setScannedText(trimmed);
      setResult(data);
      setPreview("");
      setRecent(items => [data, ...items.filter(i => i.scan_reference !== data.scan_reference)].slice(0, 4));
    } catch (err) {
      if (err?.status === 429) {
        setError({ type: "rate",    message: err.message || t.rateError });
      } else {
        setError({ type: "offline", message: err?.message || t.offlineError });
      }
    } finally {
      setLoading(false);
    }
  }

  async function handleScan(event) {
    event?.preventDefault();
    setSelectedDemo(null);
    await runScanText(content);
  }

  function runSimulator(scenario) {
    setContent(scenario.value);
    setSelectedDemo(scenario.id);
    setError(null);
    runScanText(scenario.value);
  }

  function handleArsenalTry(card) {
    if (card.action === "qr") {
      qrInputRef.current?.click();
      return;
    }
    if (card.action === "sidebar") {
      setSidebarOpen(true);
      return;
    }
    const checkerEl = document.getElementById("checker");
    if (checkerEl) checkerEl.scrollIntoView({ behavior: "smooth", block: "start" });
    if (card.action === "voice") {
      toggleVoiceInput();
      return;
    }
    if (card.scenarioId) {
      const scenario = DEMOS.find(s => s.id === card.scenarioId);
      if (scenario) runSimulator(scenario);
    }
  }

  function toggleVoiceInput() {
    if (listening && recognitionRef.current) {
      recognitionRef.current.stop();
      setListening(false);
      return;
    }
    const SpeechRec = window.SpeechRecognition || window.webkitSpeechRecognition;
    if (!SpeechRec) {
      setError({ type: "offline", message: t.voiceNoSupport });
      return;
    }
    try {
      const rec = new SpeechRec();
      rec.lang = language === "hi" ? "hi-IN" : "en-IN";
      rec.interimResults = false;
      rec.maxAlternatives = 1;
      rec.onresult = (evt) => {
        const transcript = evt.results?.[0]?.[0]?.transcript?.trim();
        if (transcript) {
          setContent(prev => (prev ? `${prev.trim()} ${transcript}` : transcript).slice(0, 5000));
        }
      };
      rec.onerror = () => setListening(false);
      rec.onend = () => setListening(false);
      recognitionRef.current = rec;
      setListening(true);
      setError(null);
      rec.start();
    } catch {
      setListening(false);
      setError({ type: "offline", message: t.voiceNoSupport });
    }
  }

  async function handleEmlFileChange(event) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    try {
      const raw = await file.text();
      const trimmed = raw.trim().slice(0, 5000);
      if (!trimmed) {
        setError({ type: "offline", message: t.emlError });
        return;
      }
      setContent(trimmed);
      setSelectedDemo(null);
      setError(null);
    } catch {
      setError({ type: "offline", message: t.emlError });
    }
  }

  async function handleTextDrop(event) {
    const file = event.dataTransfer?.files?.[0];
    if (!file) return;
    if (/\.(eml|txt)$/i.test(file.name) || file.type === "text/plain" || file.type === "message/rfc822") {
      event.preventDefault();
      try {
        const raw = await file.text();
        if (raw.trim()) {
          setContent(raw.trim().slice(0, 5000));
          setSelectedDemo(null);
          setError(null);
        }
      } catch {
        setError({ type: "offline", message: t.emlError });
      }
    }
  }

  async function copyWarningSummary() {
    if (!activeResult || !tier) return;
    const defanged = activeResult.technical_details?.defanged_url;
    const topReasons = (activeResult.reasons || []).slice(0, 2).map(r => `• ${r}`).join("\n");
    const summary = [
      `🛡️ PhishShield Alert — ${tier.label} (${activeResult.risk_score}/100)`,
      defanged ? `Safe Link: ${defanged}` : null,
      topReasons || null,
      "Do NOT click links, share OTP/PIN, or install .APK files.",
      "Report fraud: Call 1930 or visit cybercrime.gov.in",
    ].filter(Boolean).join("\n");
    try {
      await navigator.clipboard.writeText(summary);
      setSharedWarning(true);
      window.setTimeout(() => setSharedWarning(false), 1800);
    } catch {
      setError({ type: "offline", message: t.copyError });
    }
  }

  function downloadSafetyCardPng() {
    if (!activeResult || !tier) return;
    const canvas = document.createElement("canvas");
    canvas.width = 800;
    canvas.height = 440;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    ctx.fillStyle = "#081424";
    ctx.fillRect(0, 0, 800, 440);
    ctx.strokeStyle = activeResult.risk_score >= 60 ? "#ff6b6b" : activeResult.risk_score >= 25 ? "#ffce77" : "#18d9d2";
    ctx.lineWidth = 4;
    ctx.strokeRect(18, 18, 764, 404);

    ctx.fillStyle = "#18d9d2";
    ctx.font = "bold 22px system-ui, -apple-system, sans-serif";
    ctx.fillText("PHISHSHIELD SAFETY CARD", 44, 62);

    ctx.fillStyle = activeResult.risk_score >= 60 ? "#ff8b89" : activeResult.risk_score >= 25 ? "#ffce77" : "#6ce5c4";
    ctx.font = "bold 30px system-ui, -apple-system, sans-serif";
    ctx.fillText(`${tier.label} — ${activeResult.risk_score}/100`, 44, 110);

    ctx.fillStyle = "#dbe7f3";
    ctx.font = "17px system-ui, -apple-system, sans-serif";
    const lines = [
      ...(activeResult.reasons || []).slice(0, 2).map(r => `• ${r.slice(0, 82)}`),
      activeResult.technical_details?.defanged_url ? `De-fanged link: ${activeResult.technical_details.defanged_url.slice(0, 68)}` : "",
    ].filter(Boolean);
    lines.forEach((line, idx) => ctx.fillText(line, 44, 165 + idx * 36));

    ctx.fillStyle = "#0f2238";
    ctx.fillRect(44, 305, 712, 82);
    ctx.fillStyle = "#ffce77";
    ctx.font = "bold 18px system-ui, -apple-system, sans-serif";
    ctx.fillText("WHAT TO DO NEXT: Never share OTP/UPI PIN or install .APK files.", 62, 338);
    ctx.fillStyle = "#9ec0d8";
    ctx.font = "16px system-ui, -apple-system, sans-serif";
    ctx.fillText("Cyber Fraud Helpline: Call 1930  |  cybercrime.gov.in  |  Ref: " + activeResult.scan_reference, 62, 368);

    const link = document.createElement("a");
    link.download = `phishshield-${activeResult.scan_reference}.png`;
    link.href = canvas.toDataURL("image/png");
    link.click();
  }

  async function copyReference() {
    if (!activeResult?.scan_reference) return;
    try {
      await navigator.clipboard.writeText(activeResult.scan_reference);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      setError({ type: "offline", message: t.copyError });
    }
  }

  async function copyDefangedUrl(url) {
    if (!url) return;
    try {
      await navigator.clipboard.writeText(url);
      setCopiedDefanged(true);
      window.setTimeout(() => setCopiedDefanged(false), 1600);
    } catch {
      setError({ type: "offline", message: t.copyError });
    }
  }

  async function handleQrFileChange(event) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    if (typeof window.BarcodeDetector !== "function") {
      setError({ type: "offline", message: t.qrNoSupport });
      return;
    }
    try {
      const detector = new window.BarcodeDetector({ formats: ["qr_code"] });
      const bitmap = await createImageBitmap(file);
      const codes = await detector.detect(bitmap);
      if (typeof bitmap.close === "function") bitmap.close();
      const rawValue = codes?.[0]?.rawValue?.trim();
      if (!rawValue) {
        setError({ type: "offline", message: t.qrNotFound });
        return;
      }
      setContent(rawValue.slice(0, 5000));
      setSelectedDemo(null);
      setError(null);
    } catch {
      setError({ type: "offline", message: t.qrNotFound });
    }
  }

  function selectRecent(item) {
    setResult(item);
    setPreview("");
    setError(null);
  }

  /* ── JSX ──────────────────────────────────────────────────────────────── */
  return (
    <main className="ps-app" lang={language} data-theme={theme}>

      {/* NAV ─────────────────────────────────────────────────────────────── */}
      <header className="topbar">
        <a className="brand" href="#top" aria-label="PhishShield home">
          <ShieldLogo size={36}/>
          <span className="brand-text">
            <span className="brand-name">phish<span className="brand-accent">shield</span></span>
            <small>{t.tagline}</small>
          </span>
        </a>
        <div className="topbar-right">
          <button
            type="button"
            className="quick-nav-btn"
            onClick={() => setSidebarOpen(true)}
          >
            <Icon name="shield" size={14}/> {t.quickCheckTab}
          </button>
          <span className="privacy-mini">
            <span className="privacy-dot" aria-hidden="true"/>
            {t.privateBadge}
          </span>
          <span className="topbar-divider"/>
          <button
            type="button"
            className="theme-toggle"
            onClick={() => setTheme(prev => prev === "dark" ? "light" : "dark")}
            aria-label="Toggle color theme"
          >
            {theme === "dark" ? `☀️ ${t.themeLight}` : `🌙 ${t.themeDark}`}
          </button>
          <label className="sr-only" htmlFor="language">Explanation language</label>
          <select id="language" className="language-select" value={language} onChange={e => handleLanguageChange(e.target.value)}>
            <option value="en">English</option>
            <option value="hi">हिन्दी</option>
          </select>
        </div>
      </header>

      {/* HERO ────────────────────────────────────────────────────────────── */}
      <section className="hero" id="top">
        <div className="hero-copy">
          <div className="eyebrow"><span className="eyebrow-dot"/>{t.eyebrow}</div>
          <h1>
            {t.heroTitleTop}<br/>
            <em>{t.heroTitleAccent}</em>
          </h1>
          <p>{t.heroDesc}</p>
          <div className="trust-strip">
            <div className="trust-item">
              <span className="trust-icon">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                  <path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11Z"/><path d="m9 12 2 2 4-4"/>
                </svg>
              </span>
              <span><b>{t.trust[0].title}</b><small>{t.trust[0].sub}</small></span>
            </div>
            <div className="trust-item">
              <span className="trust-icon"><span className="lang-glyph">अ</span></span>
              <span><b>{t.trust[1].title}</b><small>{t.trust[1].sub}</small></span>
            </div>
            <div className="trust-item">
              <span className="trust-icon">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                  <rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 1 1 8 0v3"/>
                </svg>
              </span>
              <span><b>{t.trust[2].title}</b><small>{t.trust[2].sub}</small></span>
            </div>
          </div>
        </div>

        <div className="hero-art" aria-hidden="true">
          <div className="art-glow art-glow-teal"/>
          <div className="art-glow art-glow-purple"/>
          <div className="orbit orbit-one"/>
          <div className="orbit orbit-two"/>
          <div className="shield-wrap"><HeroShield/></div>
          <div className="float-card float-top">
            <span className="float-dot teal-dot"/>
            {t.floatTop}
          </div>
          <div className="float-card float-bottom">
            <span className="mini-bars"><i/><i/><i/></span>
            {t.floatBottom}
          </div>
        </div>
      </section>

      {/* STORY + ALL FEATURES (RED BOX AREA) ─────────────────────────────── */}
      <section className="story-section" aria-labelledby="why-title">
        <div className="story-intro">
          <span className="step-label">{t.problemEyebrow}</span>
          <h2 id="why-title">{t.problemTitleTop}<br/><em>{t.problemTitleAccent}</em></h2>
          <p>{t.problemDesc}</p>
        </div>

        <div className="arsenal-filters story-filters" role="tablist" aria-label="Filter PhishShield features">
          {t.arsenalFilters.map(f => (
            <button
              key={f.id}
              type="button"
              role="tab"
              aria-selected={arsenalFilter === f.id}
              className={`arsenal-filter-btn${arsenalFilter === f.id ? " active" : ""}`}
              onClick={() => setArsenalFilter(f.id)}
            >
              {f.label}
            </button>
          ))}
        </div>

        <div className="arsenal-grid">
          {t.arsenalCards
            .filter(card => arsenalFilter === "all" || card.cat === arsenalFilter)
            .map(card => (
              <article key={card.id} className={`arsenal-card cat-${card.cat}`}>
                <div className="arsenal-card-top">
                  <span className="arsenal-badge">{card.badge}</span>
                  {(card.scenarioId || card.action) && (
                    <button
                      type="button"
                      className="arsenal-try-btn"
                      onClick={() => handleArsenalTry(card)}
                    >
                      {t.arsenalTryBtn}
                    </button>
                  )}
                </div>
                <h3>{card.title}</h3>
                <p>{card.desc}</p>
              </article>
            ))}
        </div>
      </section>

      {/* HOW IT WORKS ────────────────────────────────────────────────────── */}
      <section className="how-section" aria-labelledby="how-title">
        <div className="section-title-block">
          <span className="step-label">{t.howEyebrow}</span>
          <h2 id="how-title">{t.howTitle}</h2>
          <p>{t.howDesc}</p>
        </div>
        <div className="steps-grid">
          <article className="how-step">
            <span className="step-number">01</span>
            <span className="how-icon"><svg viewBox="0 0 24 24"><path d="M8 5h8M8 9h8M8 13h5M6 3h12a2 2 0 0 1 2 2v14H4V5a2 2 0 0 1 2-2Z"/></svg></span>
            <b>{t.steps[0].title}</b><p>{t.steps[0].desc}</p>
          </article>
          <article className="how-step">
            <span className="step-number">02</span>
            <span className="how-icon"><svg viewBox="0 0 24 24"><circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 5 5M8 10h5M10.5 7.5v5"/></svg></span>
            <b>{t.steps[1].title}</b><p>{t.steps[1].desc}</p>
          </article>
          <article className="how-step">
            <span className="step-number">03</span>
            <span className="how-icon"><svg viewBox="0 0 24 24"><path d="M12 3 3 7v5c0 5 4 8 9 9 5-1 9-4 9-9V7l-9-4Z"/><path d="m8 12 2.5 2.5L16 9"/></svg></span>
            <b>{t.steps[2].title}</b><p>{t.steps[2].desc}</p>
          </article>
          <article className="how-step">
            <span className="step-number">04</span>
            <span className="how-icon"><svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11Z"/><path d="M9 12h6"/></svg></span>
            <b>{t.steps[3].title}</b><p>{t.steps[3].desc}</p>
          </article>
        </div>
      </section>

      {/* RISK GUIDE ──────────────────────────────────────────────────────── */}
      <section className="risk-guide" aria-labelledby="risk-guide-title">
        <div className="risk-guide-copy">
          <span className="step-label">{t.guideEyebrow}</span>
          <h2 id="risk-guide-title">{t.guideTitle}</h2>
          <p>{t.guideDesc}</p>
        </div>
        <div className="risk-guide-cards">
          <article className="guide-tier low-tier">
            <span className="guide-range">{t.guideTiers[0].range}</span>
            <b>{t.guideTiers[0].label}</b><p>{t.guideTiers[0].desc}</p>
          </article>
          <article className="guide-tier suspicious-tier">
            <span className="guide-range">{t.guideTiers[1].range}</span>
            <b>{t.guideTiers[1].label}</b><p>{t.guideTiers[1].desc}</p>
          </article>
          <article className="guide-tier dangerous-tier">
            <span className="guide-range">{t.guideTiers[2].range}</span>
            <b>{t.guideTiers[2].label}</b><p>{t.guideTiers[2].desc}</p>
          </article>
        </div>
      </section>

      {/* PRIVACY ─────────────────────────────────────────────────────────── */}
      <section className="privacy-section" aria-labelledby="privacy-title">
        <div className="privacy-emblem">
          <svg viewBox="0 0 80 90" aria-hidden="true">
            <defs>
              <linearGradient id="pe-g" x1="0" y1="0" x2="80" y2="90" gradientUnits="userSpaceOnUse">
                <stop offset="0%" stopColor="#18D9D2"/>
                <stop offset="100%" stopColor="#A855F7"/>
              </linearGradient>
            </defs>
            <path d="M40 4 70 16v22c0 21-13 34-30 44C23 72 10 59 10 38V16L40 4Z" stroke="url(#pe-g)" strokeWidth="2" fill="none"/>
            <path d="m27 42 9 9 18-20" stroke="url(#pe-g)" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"/>
          </svg>
        </div>
        <div className="privacy-copy">
          <span className="step-label">{t.privacyEyebrow}</span>
          <h2 id="privacy-title">{t.privacyTitle}</h2>
          <p>{t.privacyDesc}</p>
          <div className="privacy-points">{t.privacyPoints.map(pt => <span key={pt}>{pt}</span>)}</div>
        </div>
      </section>

      {/* FAQ ─────────────────────────────────────────────────────────────── */}
      <section className="faq-section" aria-labelledby="faq-title">
        <div className="section-title-block">
          <span className="step-label">{t.faqEyebrow}</span>
          <h2 id="faq-title">{t.faqTitle}</h2>
        </div>
        <div className="faq-grid">
          {t.faqs.map(item => (
            <article key={item.q}><b>{item.q}</b><p>{item.a}</p></article>
          ))}
        </div>
      </section>

      {/* WORKSPACE ───────────────────────────────────────────────────────── */}
      <section className="workspace" id="checker">

        {/* INPUT COLUMN */}
        <div className="input-column">
          <div className="section-heading">
            <div>
              <span className="step-label">{t.yourCheck}</span>
              <h2>{t.checkHeading}</h2>
            </div>
            <span className="input-count">{content.length.toLocaleString()} <i>/ 5,000</i></span>
          </div>

          <form className="input-card" onSubmit={handleScan}>
            <label htmlFor="scan-content" className="sr-only">{t.placeholder}</label>
            <textarea
              id="scan-content"
              minLength={3}
              maxLength={5000}
              value={content}
              onChange={e => setContent(e.target.value)}
              onDrop={handleTextDrop}
              placeholder={t.placeholder}
            />
            <div className="input-footer">
              <span><Icon name="lock" size={13}/> {t.textOnlyNote}</span>
              <div className="input-footer-actions">
                <input
                  ref={qrInputRef}
                  type="file"
                  accept="image/*"
                  className="sr-only"
                  onChange={handleQrFileChange}
                />
                <input
                  ref={emlInputRef}
                  type="file"
                  accept=".eml,.txt,message/rfc822,text/plain"
                  className="sr-only"
                  onChange={handleEmlFileChange}
                />
                <button
                  type="button"
                  className={`qr-scan-btn${listening ? " listening" : ""}`}
                  onClick={toggleVoiceInput}
                >
                  <Icon name="mic" size={13}/> {listening ? t.voiceListening : t.voiceBtn}
                </button>
                <button type="button" className="qr-scan-btn" onClick={() => emlInputRef.current?.click()}>
                  <Icon name="file" size={13}/> {t.emlBtn}
                </button>
                <button type="button" className="qr-scan-btn" onClick={() => qrInputRef.current?.click()}>
                  <Icon name="eye" size={13}/> {t.scanQrBtn}
                </button>
                <button type="button" className="clear-button" onClick={() => { setContent(""); setError(null); setSelectedDemo(null); }}>
                  <Icon name="close" size={14}/> {t.clearBtn}
                </button>
              </div>
            </div>
            <div className="form-actions">
              <button className="scan-button" type="submit" disabled={content.trim().length < 3 || loading}>
                {loading
                  ? <><span className="spinner"/> {t.checkingBtn}</>
                  : <>{t.checkBtn} <Icon name="arrow" size={17}/></>
                }
              </button>
              <span className="no-click-note">
                <Icon name="shield" size={14}/> {t.neverVisit}
              </span>
            </div>
          </form>

          {/* Demo chips (all features) */}
          <div className="demo-area">
            <div className="demo-title">
              {t.demoTitle} <span className="demo-title-sep">·</span> <span className="demo-sub">{t.demoSub}</span>
            </div>
            <div className="demo-chips">
              {DEMOS.map(demo => (
                <button
                  type="button"
                  key={demo.id}
                  className={`demo-chip ${demo.kind}${selectedDemo === demo.id ? " chip-selected" : ""}`}
                  onClick={() => useDemo(demo)}
                >
                  {t.demoLabels[demo.id]}<span className="chip-arrow">↗</span>
                </button>
              ))}
            </div>
          </div>

          {/* Safety note */}
          <div className="safety-note">
            <Icon name="alert" size={17}/>
            <p><b>{t.rememberLabel}</b> {t.rememberTextPre}<u>{t.rememberNot}</u>{t.rememberTextPost}</p>
          </div>
        </div>

        {/* RESULT COLUMN */}
        <div className="result-column">
          <div className="result-heading">
            <div>
              <span className="step-label">{t.yourResult}</span>
              <h2>{t.resultHeading}</h2>
            </div>
            <span className="live-indicator">
              <span className="live-dot"/>
              {result ? t.liveCheck : t.samplePreview}
            </span>
          </div>

          {/* Error banner */}
          {error && (
            <div className={`alert-banner ${error.type}`} role="alert">
              <span className="alert-symbol"><Icon name="alert" size={18}/></span>
              <div>
                <b>{error.type === "rate" ? t.rateAlertTitle : t.offlineAlertTitle}</b>
                <p>{error.message}</p>
              </div>
              <button type="button" onClick={() => setError(null)} aria-label="Dismiss alert">
                <Icon name="close" size={16}/>
              </button>
            </div>
          )}

          {/* Result card */}
          {activeResult && tier ? (
            <article className={`result-card ${tier.tone}`}>
              <div className="result-topline">
                <span className="result-kicker"><Icon name="spark" size={14}/> {t.riskOverview}</span>
                <span className="type-pill">{activeResult.content_type?.toLowerCase() === "url" ? t.typeUrl : t.typeMsg}</span>
              </div>

              <div className="verdict-row">
                <RiskGauge score={activeResult.risk_score} tier={tier} scoreLabel={t.riskScoreLabel}/>
                <div className="verdict-copy">
                  <span className={`verdict-badge ${tier.tone}`}>
                    <i/> {tier.label}
                  </span>
                  <h3>{t.verdictHeadlines[tier.tone]}</h3>
                  <p>{t.verdictSubs[tier.tone]}</p>
                </div>
              </div>

              {/* Plain language explanation */}
              <div className="explanation-card">
                <div className="explanation-icon"><Icon name="shield" size={18}/></div>
                <div>
                  <span>{t.plainLangLabel}</span>
                  <p>{activeResult.explanation}</p>
                </div>
              </div>

              {/* Campaign alert */}
              {activeResult.campaign_detected === true && (
                <div className="campaign-pill"><span>↗</span> {t.campaignBadge}</div>
              )}

              {/* Evidence list */}
              <div className="evidence-section">
                <div className="subsection-heading">
                  <h4>{t.noticedHeading}</h4>
                  <span>{activeResult.reasons.length} {t.indicatorsWord}</span>
                </div>
                {activeResult.reasons.length
                  ? <ul className="evidence-list">
                      {activeResult.reasons.map((reason, idx) => (
                        <li key={`${idx}-${reason}`}>
                          <span className="evidence-check"><Icon name="alert" size={13}/></span>
                          {reason}
                        </li>
                      ))}
                    </ul>
                  : <p className="empty-evidence">{t.emptyEvidence}</p>
                }
              </div>

              {/* Highlighted suspicious triggers */}
              {result && result.matched_terms?.length > 0 && scannedText && (
                <div className="highlight-box">
                  <span className="highlight-label">{t.highlightsTitle}</span>
                  <p className="highlight-text">{renderHighlightedText(scannedText, result.matched_terms)}</p>
                </div>
              )}

              {/* What to do next playbook */}
              {playbookSteps.length > 0 && (
                <div className={`playbook-card ${tier.tone}`}>
                  <div className="playbook-head">
                    <Icon name="shield" size={15}/>
                    <b>{t.playbookTitle}</b>
                  </div>
                  <ul>
                    {playbookSteps.map((step, i) => <li key={i}>{step}</li>)}
                  </ul>
                </div>
              )}

              {/* Low-risk unverified notice */}
              {tier.key === "low" && (
                <div className="unverified-callout">
                  <Icon name="alert" size={15}/>
                  <p>{t.unverifiedNote}</p>
                </div>
              )}

              {/* ML confidence */}
              {activeResult.ml_probability !== null && activeResult.ml_probability !== undefined && (
                <div className="ml-signal">
                  <div className="ml-label">
                    <span>{t.mlSignalLabel}</span>
                    <b>{(Number(activeResult.ml_probability) * 100).toFixed(1)}%</b>
                  </div>
                  <div className="ml-track">
                    <span style={{ width: `${Math.max(0, Math.min(100, Number(activeResult.ml_probability) * 100))}%` }}/>
                  </div>
                  <small>{t.mlSignalNote}</small>
                </div>
              )}

              {/* Technical details (progressive disclosure) */}
              {activeResult.technical_details && (
                <details className="tech-details">
                  <summary>
                    <span>{t.techDetailsTitle}</span>
                    <small>{activeResult.technical_details.triggered_rules?.length ?? 0} rules</small>
                  </summary>
                  <div className="tech-details-body">
                    <p className="tech-details-note">{t.techDetailsSub}</p>
                    <dl className="tech-kv-grid">
                      <div><dt>Parsed host</dt><dd>{activeResult.technical_details.parsed_host || "Not specified"}</dd></div>
                      <div><dt>Host type</dt><dd>{activeResult.technical_details.host_type === "ip_address" ? "IP address" : activeResult.technical_details.host_type || "Not specified"}</dd></div>
                      <div><dt>Port</dt><dd>{activeResult.technical_details.port ?? "Not specified"}</dd></div>
                      <div><dt>Scheme</dt><dd>{activeResult.technical_details.scheme || "not specified"}</dd></div>
                      <div><dt>HTTPS</dt><dd>{activeResult.technical_details.https || "not specified"}</dd></div>
                      <div><dt>Top-level domain</dt><dd>{activeResult.technical_details.top_level_domain || "Not applicable"}</dd></div>
                      <div><dt>URL length</dt><dd>{activeResult.technical_details.url_length ?? "Not applicable"}</dd></div>
                      <div><dt>Number of subdomains</dt><dd>{activeResult.technical_details.subdomain_count ?? "Not applicable"}</dd></div>
                    </dl>
                    {activeResult.technical_details.defanged_url && (
                      <div className="defang-row">
                        <div>
                          <span>De-fanged safe link</span>
                          <code>{activeResult.technical_details.defanged_url}</code>
                        </div>
                        <button
                          type="button"
                          className="copy-button"
                          onClick={() => copyDefangedUrl(activeResult.technical_details.defanged_url)}
                        >
                          <Icon name={copiedDefanged ? "check" : "copy"} size={13}/>
                          {copiedDefanged ? t.copiedDefanged : t.copyDefanged}
                        </button>
                      </div>
                    )}
                    {activeResult.technical_details.upi_details && (
                      <div className="sub-inspector-box">
                        <h5>UPI Intent Breakdown</h5>
                        <dl className="tech-kv-grid">
                          <div><dt>Payee VPA (pa)</dt><dd>{activeResult.technical_details.upi_details.pa}</dd></div>
                          <div><dt>Payee Name (pn)</dt><dd>{activeResult.technical_details.upi_details.pn}</dd></div>
                          <div><dt>Amount (am)</dt><dd>{activeResult.technical_details.upi_details.am}</dd></div>
                          <div><dt>Note (tn)</dt><dd>{activeResult.technical_details.upi_details.tn}</dd></div>
                        </dl>
                      </div>
                    )}
                    {activeResult.technical_details.email_headers && (
                      <div className="sub-inspector-box">
                        <h5>Email Header Spoof Check</h5>
                        <dl className="tech-kv-grid">
                          <div><dt>From Domain</dt><dd>{activeResult.technical_details.email_headers.from_domain}</dd></div>
                          <div><dt>Reply-To Domain</dt><dd>{activeResult.technical_details.email_headers.reply_to_domain}</dd></div>
                          <div><dt>Return-Path Domain</dt><dd>{activeResult.technical_details.email_headers.return_path_domain}</dd></div>
                          <div><dt>Auth Failures</dt><dd>{activeResult.technical_details.email_headers.auth_failures?.join(", ") || "None detected"}</dd></div>
                        </dl>
                      </div>
                    )}
                    <div className="tech-lists">
                      <div>
                        <h5>Detected URL indicators</h5>
                        {activeResult.technical_details.detected_url_indicators?.length ? (
                          <ul>{activeResult.technical_details.detected_url_indicators.map((item, i) => <li key={i}>{item}</li>)}</ul>
                        ) : <p className="tech-empty">None</p>}
                      </div>
                      <div>
                        <h5>Detected message indicators</h5>
                        {activeResult.technical_details.detected_message_indicators?.length ? (
                          <ul>{activeResult.technical_details.detected_message_indicators.map((item, i) => <li key={i}>{item}</li>)}</ul>
                        ) : <p className="tech-empty">None</p>}
                      </div>
                      <div>
                        <h5>Triggered rules &amp; score contributions</h5>
                        {activeResult.technical_details.triggered_rules?.length ? (
                          <ul className="tech-rules-list">
                            {activeResult.technical_details.triggered_rules.map((rule, i) => (
                              <li key={`${rule.rule_id}-${i}`}>
                                <code>{rule.rule_id}</code> <b>+{rule.score}</b> — {rule.reason}
                              </li>
                            ))}
                          </ul>
                        ) : <p className="tech-empty">No risk rules triggered (0 points).</p>}
                      </div>
                    </div>
                  </div>
                </details>
              )}

              {/* Scan reference & Share Safety Card */}
              <div className="reference-row">
                <div>
                  <span>{t.scanRefLabel}</span>
                  <strong>{activeResult.scan_reference}</strong>
                </div>
                <div className="ref-actions">
                  <button type="button" onClick={copyWarningSummary} className="copy-button">
                    <Icon name={sharedWarning ? "check" : "share"} size={14}/> {sharedWarning ? t.sharedWarning : t.shareWarning}
                  </button>
                  <button type="button" onClick={downloadSafetyCardPng} className="copy-button">
                    <Icon name="file" size={14}/> {t.downloadCard}
                  </button>
                  <button type="button" onClick={copyReference} className="copy-button">
                    <Icon name={copied ? "check" : "copy"} size={14}/> {copied ? t.copiedRef : t.copyRef}
                  </button>
                </div>
              </div>

              {isPreview && <div className="preview-caption">{t.previewCaption}</div>}
            </article>
          ) : !error ? (
            <div className="empty-result">
              <div className="empty-orbit"><Icon name="shield" size={35}/></div>
              <h3>{t.emptyTitle}</h3>
              <p>{t.emptyDescPre}<b>{t.emptyDescBold}</b>{t.emptyDescPost}</p>
              <div className="empty-foot"><Icon name="lock" size={14}/> {t.emptyFoot}</div>
            </div>
          ) : null}

          {/* Dev preview switcher */}
          <div className="preview-switcher">
            <span>{t.previewResult}</span>
            <div className="preview-options">
              {["low","suspicious","dangerous","rate"].map(key => (
                <button
                  key={key}
                  className={preview === key && !result ? "selected" : ""}
                  onClick={() => showPreview(key)}
                  type="button"
                >
                  {t[key === "low" ? "previewLow" : key === "suspicious" ? "previewSuspicious" : key === "dangerous" ? "previewDangerous" : "previewRate"]}
                </button>
              ))}
            </div>
          </div>

          {/* Recent checks */}
          <div className="recent-card">
            <div className="recent-heading">
              <div><Icon name="clock" size={16}/><b>{t.recentTitle}</b></div>
              <span>{t.recentSub}</span>
            </div>
            {recent.length
              ? <ul>
                  {recent.map(item => {
                    const itemTier = getTier(item.risk_score, t);
                    return (
                      <li key={item.scan_reference}>
                        <button type="button" onClick={() => selectRecent(item)}>
                          <span className={`recent-dot ${itemTier.tone}`}/>
                          <span className="recent-type">{item.content_type === "url" ? t.typeUrl : t.typeMsg}</span>
                          <span className="recent-ref">{item.scan_reference}</span>
                          <span className={`recent-score ${itemTier.tone}`}>{item.risk_score}/100</span>
                          <Icon name="arrow" size={14}/>
                        </button>
                      </li>
                    );
                  })}
                </ul>
              : <p className="recent-empty">{t.recentEmpty}</p>
            }
          </div>
        </div>
      </section>

      {/* FOOTER ──────────────────────────────────────────────────────────── */}
      <footer className="footer">
        <div className="footer-brand"><ShieldLogo size={20}/> PhishShield</div>
        <span>{t.footerDesc}</span>
        <span className="footer-tag">{t.tagline}</span>
      </footer>

      {/* PERSISTENT QUICK-TEST SIDEBAR ────────────────────────────────────── */}
      <button
        type="button"
        className="sidebar-edge-tab"
        onClick={() => setSidebarOpen(true)}
        aria-label={t.quickCheckTitle}
      >
        <Icon name="shield" size={15}/>
        <span>{t.quickCheckTab}</span>
      </button>

      {sidebarOpen && (
        <div className="quick-sidebar-backdrop" onClick={() => setSidebarOpen(false)} aria-hidden="true"/>
      )}

      <aside className={`quick-sidebar${sidebarOpen ? " open" : ""}`} aria-label={t.quickCheckTitle} aria-hidden={!sidebarOpen}>
        <div className="quick-sidebar-header">
          <div>
            <span className="step-label">{t.yourCheck}</span>
            <h3>{t.quickCheckTitle}</h3>
            <p>{t.quickCheckSub}</p>
          </div>
          <button type="button" className="quick-close-btn" onClick={() => setSidebarOpen(false)} aria-label="Close sidebar">
            <Icon name="close" size={18}/>
          </button>
        </div>

        <div className="quick-sidebar-body">
          <div className="demo-chips">
            {DEMOS.map(demo => (
              <button
                type="button"
                key={`sb-${demo.id}`}
                className={`demo-chip ${demo.kind}${selectedDemo === demo.id ? " chip-selected" : ""}`}
                onClick={() => useDemo(demo)}
              >
                {t.demoLabels[demo.id]}<span className="chip-arrow">↗</span>
              </button>
            ))}
          </div>

          <form className="input-card quick-input-card" onSubmit={handleScan}>
            <label htmlFor="quick-scan-content" className="sr-only">{t.placeholder}</label>
            <textarea
              id="quick-scan-content"
              minLength={3}
              maxLength={5000}
              value={content}
              onChange={e => setContent(e.target.value)}
              placeholder={t.placeholder}
            />
            <div className="input-footer">
              <span><Icon name="lock" size={13}/> {t.textOnlyNote}</span>
              <div className="input-footer-actions">
                <input
                  ref={qrInputRef}
                  type="file"
                  accept="image/*"
                  className="sr-only"
                  onChange={handleQrFileChange}
                />
                <button
                  type="button"
                  className={`qr-scan-btn${listening ? " listening" : ""}`}
                  onClick={toggleVoiceInput}
                >
                  <Icon name="mic" size={13}/> {listening ? t.voiceListening : t.voiceBtn}
                </button>
                <button type="button" className="qr-scan-btn" onClick={() => emlInputRef.current?.click()}>
                  <Icon name="file" size={13}/> {t.emlBtn}
                </button>
                <button type="button" className="qr-scan-btn" onClick={() => qrInputRef.current?.click()}>
                  <Icon name="eye" size={13}/> {t.scanQrBtn}
                </button>
                <button type="button" className="clear-button" onClick={() => { setContent(""); setError(null); setSelectedDemo(null); }}>
                  <Icon name="close" size={14}/> {t.clearBtn}
                </button>
              </div>
            </div>
            <button className="scan-button quick-scan-btn" type="submit" disabled={content.trim().length < 3 || loading}>
              {loading
                ? <><span className="spinner"/> {t.checkingBtn}</>
                : <>{t.checkBtn} <Icon name="arrow" size={17}/></>
              }
            </button>
          </form>

          {error && (
            <div className={`alert-banner ${error.type}`} role="alert">
              <span className="alert-symbol"><Icon name="alert" size={18}/></span>
              <div>
                <b>{error.type === "rate" ? t.rateAlertTitle : t.offlineAlertTitle}</b>
                <p>{error.message}</p>
              </div>
            </div>
          )}

          {result && tier && (
            <div className={`quick-mini-result ${tier.tone}`}>
              <div className="quick-mini-head">
                <span className={`verdict-badge ${tier.tone}`}><i/> {tier.label}</span>
                <strong>{result.risk_score}<small>/100</small></strong>
              </div>
              <p>{result.explanation}</p>
              <a
                href="#checker"
                className="quick-full-link"
                onClick={() => setSidebarOpen(false)}
              >
                {t.viewFullResult} <Icon name="arrow" size={14}/>
              </a>
            </div>
          )}
        </div>
      </aside>

    </main>
  );
}

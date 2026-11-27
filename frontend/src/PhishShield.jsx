import React, { useEffect, useMemo, useState } from "react";
import { DEFAULT_API_URL, submitScan } from "./api.js";
import "./PhishShield.css";

const API_URL = import.meta.env.VITE_API_URL || DEFAULT_API_URL;

const DEMOS = [
  { id: "low",   kind: "mint",   value: "https://www.example.com" },
  { id: "kyc",   kind: "amber",  value: "Your KYC will expire today. Verify now at http://198.51.100.42/login and share your OTP." },
  { id: "brand", kind: "coral",  value: "https://paypal-verify.example/account/login" },
  { id: "short", kind: "violet", value: "http://bit.ly/verify-prize-now" },
];

const MOCKS_BY_LANG = {
  en: {
    low: {
      scan_reference: "261127000101", risk_score: 12, risk_level: "Low Risk", content_type: "url",
      reasons: ["No obvious urgency or credential request detected.", "The domain uses a familiar example-domain pattern."],
      explanation: "We did not find strong warning signs in this text. That does not prove the destination is safe—this link is still unverified. Only visit it if you expected it and trust the sender.",
      ml_probability: 0.08, campaign_detected: false,
    },
    suspicious: {
      scan_reference: "261127000102", risk_score: 46, risk_level: "Suspicious", content_type: "url",
      reasons: ["The domain contains a brand-like name with an unusual extra word.", "The URL includes a sign-in path that may be used to collect credentials."],
      explanation: "This link has a few warning signs. The address resembles a familiar service, but the domain is not that service's official domain. Do not enter a password or payment details.",
      ml_probability: 0.71, campaign_detected: false,
    },
    dangerous: {
      scan_reference: "261127000103", risk_score: 94, risk_level: "Dangerous", content_type: "message",
      reasons: ["Creates urgency with a KYC-expiry threat.", "Requests an OTP, which should never be shared with another person.", "Uses a raw IP address instead of a recognizable organization domain."],
      explanation: "This message is very likely to be a scam. It pressures you to act quickly and asks for your OTP. Do not reply, share a code, or use the link. Contact the organization using its official app or a number you already trust.",
      ml_probability: 0.98, campaign_detected: true,
    },
  },
  hi: {
    low: {
      scan_reference: "261127000101", risk_score: 12, risk_level: "Low Risk", content_type: "url",
      reasons: ["टेक्स्ट में कोई स्पष्ट जल्दबाज़ी या OTP/पासवर्ड की माँग नहीं मिली।", "डोमेन एक सामान्य उदाहरण-डोमेन पैटर्न का उपयोग करता है।"],
      explanation: "इस टेक्स्ट में बड़े खतरे के संकेत नहीं मिले हैं। फिर भी यह साबित नहीं होता कि वेबसाइट सुरक्षित है—यह लिंक अभी भी असत्यापित है। केवल तभी खोलें जब आपको इसकी उम्मीद हो और भेजने वाले पर भरोसा हो।",
      ml_probability: 0.08, campaign_detected: false,
    },
    suspicious: {
      scan_reference: "261127000102", risk_score: 46, risk_level: "Suspicious", content_type: "url",
      reasons: ["डोमेन में किसी जाने-पहचाने ब्रांड जैसा नाम और एक असामान्य अतिरिक्त शब्द है।", "URL में साइन-इन पेज जैसा रास्ता है जिसका उपयोग लॉगिन जानकारी चुराने के लिए हो सकता है।"],
      explanation: "इस लिंक में कुछ चेतावनी के संकेत हैं। पता किसी जानी-मानी सेवा जैसा दिखता है, लेकिन यह उसका आधिकारिक डोमेन नहीं है। पासवर्ड या भुगतान जानकारी दर्ज न करें।",
      ml_probability: 0.71, campaign_detected: false,
    },
    dangerous: {
      scan_reference: "261127000103", risk_score: 94, risk_level: "Dangerous", content_type: "message",
      reasons: ["KYC बंद होने की धमकी देकर जल्दबाज़ी का दबाव बनाता है।", "OTP माँगता है, जिसे कभी किसी के साथ साझा नहीं करना चाहिए।", "आधिकारिक वेबसाइट के बजाय सीधे IP नंबर का उपयोग करता है।"],
      explanation: "यह संदेश धोखाधड़ी (स्कैम) होने की पूरी संभावना है। यह तुरंत कार्रवाई करने का दबाव डालता है और OTP माँगता है। जवाब न दें, कोड साझा न करें और लिंक न खोलें। सीधे आधिकारिक ऐप या भरोसेमंद नंबर से संपर्क करें।",
      ml_probability: 0.98, campaign_detected: true,
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
    problemDesc: "One urgent text can make anyone pause: a KYC warning, a parcel delay, a too-good-to-be-true job offer. PhishShield helps turn that moment of uncertainty into a clearer next step.",
    threats: [
      { title: "Digital Arrest, KYC & OTP scams", desc: "Fake CBI, customs, or TRAI threats, KYC expiry alerts, and screen-sharing traps (AnyDesk/TeamViewer)." },
      { title: "UPI, QR & impersonation links", desc: "Tricks asking for your UPI PIN or QR scan to receive money, plus look-alike bank/gov URLs and risky domains." },
      { title: "Malicious .APK, challan & prize scams", desc: "Fake RTO e-challan or PM-Kisan .apk downloads, parcel fees, and unexpected rewards." },
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
      { q: "Does 'Low Risk' mean safe?", a: "No. It means no strong warning signs were identified. Unknown links remain unverified, so use your judgement." },
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
    demoLabels: { low: "Low-risk URL", kyc: "KYC + OTP scam", brand: "Brand look-alike", short: "Shortened link" },
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
    verdictSubs: { low: "Still unverified. Stay alert.", suspicious: "Some details deserve caution.", dangerous: "This has multiple high-risk signals." },
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
    problemDesc: "एक ज़रूरी-सा दिखने वाला संदेश किसी को भी उलझन में डाल सकता है—KYC चेतावनी, पार्सल अटकने का संदेश, या आकर्षक नौकरी का प्रस्ताव। PhishShield उस उलझन को साफ़ जानकारी में बदलता है।",
    threats: [
      { title: "डिजिटल अरेस्ट, KYC व OTP ठगी", desc: "नकली CBI/कस्टम या TRAI धमकी, KYC बंद होने के अलर्ट, और स्क्रीन-शेयरिंग (AnyDesk/TeamViewer) जाल।" },
      { title: "UPI, QR व नकली ब्रांड लिंक", desc: "पैसे पाने के नाम पर UPI PIN या QR स्कैन कराने की चाल, नकली बैंक/सरकारी लिंक और संदिग्ध डोमेन।" },
      { title: "खतरनाक .APK, ई-चालान व इनाम ठगी", desc: "नकली RTO ई-चालान या PM-Kisan .apk डाउनलोड, पार्सल शुल्क और अनपेक्षित इनाम।" },
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
      { q: "क्या 'कम जोखिम' का मतलब सुरक्षित है?", a: "नहीं। इसका मतलब केवल इतना है कि टेक्स्ट में आम ठगी के संकेत नहीं मिले। अनजान लिंक फिर भी असत्यापित रहते हैं।" },
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
    demoLabels: { low: "कम जोखिम URL", kyc: "KYC + OTP ठगी", brand: "नकली ब्रांड लिंक", short: "छोटा किया लिंक" },
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
    verdictSubs: { low: "यह लिंक अभी भी असत्यापित है, सतर्क रहें।", suspicious: "कुछ संकेत संदिग्ध हैं—आधिकारिक स्रोत से जांचें।", dangerous: "इसमें कई गंभीर ठगी के संकेत मिले हैं।" },
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
    explanation:   data?.explanation || "No plain-language explanation was provided.",
    scan_reference: String(data?.scan_reference || "Unavailable"),
    content_type:  data?.content_type || "message",
  };
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
  const [selectedDemo, setSelectedDemo] = useState(null);

  useEffect(() => {
    document.body.dataset.theme = theme;
    try { window.localStorage.setItem("ps_theme", theme); }
    catch { /* ignore */ }
  }, [theme]);

  const t            = COPY[language]      || COPY.en;
  const mocks        = MOCKS_BY_LANG[language] || MOCKS_BY_LANG.en;
  const activeResult = result || (preview === "rate" ? null : mocks[preview]);
  const tier         = useMemo(() => (activeResult ? getTier(activeResult.risk_score, t) : null), [activeResult, t]);
  const isPreview    = !result && preview !== "rate";

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

  async function handleScan(event) {
    event?.preventDefault();
    if (content.trim().length < 3 || loading) return;
    setLoading(true);
    setError(null);
    setResult(null);
    setSelectedDemo(null);
    try {
      // Submitted text is sent only to the configured analysis API. This app never
      // opens, fetches, previews, or executes a URL found in the submitted content.
      const data = normalizeResult(await submitScan({ content: content.trim(), language, apiUrl: API_URL }));
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

      {/* STORY ───────────────────────────────────────────────────────────── */}
      <section className="story-section" aria-labelledby="why-title">
        <div className="story-intro">
          <span className="step-label">{t.problemEyebrow}</span>
          <h2 id="why-title">{t.problemTitleTop}<br/><em>{t.problemTitleAccent}</em></h2>
          <p>{t.problemDesc}</p>
        </div>
        <div className="threat-grid">
          <article className="threat-card">
            <span className="threat-symbol amber-symbol">!</span>
            <div><b>{t.threats[0].title}</b><p>{t.threats[0].desc}</p></div>
          </article>
          <article className="threat-card">
            <span className="threat-symbol coral-symbol">↗</span>
            <div><b>{t.threats[1].title}</b><p>{t.threats[1].desc}</p></div>
          </article>
          <article className="threat-card">
            <span className="threat-symbol violet-symbol">%</span>
            <div><b>{t.threats[2].title}</b><p>{t.threats[2].desc}</p></div>
          </article>
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
              placeholder={t.placeholder}
            />
            <div className="input-footer">
              <span><Icon name="lock" size={13}/> {t.textOnlyNote}</span>
              <button type="button" className="clear-button" onClick={() => { setContent(""); setError(null); setSelectedDemo(null); }}>
                <Icon name="close" size={14}/> {t.clearBtn}
              </button>
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

          {/* Demo chips */}
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

              {/* Scan reference */}
              <div className="reference-row">
                <div>
                  <span>{t.scanRefLabel}</span>
                  <strong>{activeResult.scan_reference}</strong>
                </div>
                <button type="button" onClick={copyReference} className="copy-button">
                  <Icon name={copied ? "check" : "copy"} size={14}/> {copied ? t.copiedRef : t.copyRef}
                </button>
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

    </main>
  );
}

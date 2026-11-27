import requests

from app import config

HINDI_LEVELS = {
    "Safe": "सुरक्षित (Safe)",
    "Suspicious": "संदिग्ध (Suspicious)",
    "Dangerous": "खतरनाक (Dangerous)",
}


def _fallback_explanation(level: str, reasons: list[str], language: str) -> str:
    joined_reasons = " ".join(reasons)
    if language == "hi":
        hindi_level = HINDI_LEVELS.get(level, level)
        advice = (
            "इस लिंक पर क्लिक न करें और न ही OTP, PIN या पासवर्ड साझा करें।"
            if level != "Safe"
            else "कोई सामान्य फ़िशिंग संकेत नहीं मिला, लेकिन किसी भी लिंक पर भरोसा करने से पहले वेबसाइट की जांच जरूर करें।"
        )
        return f"यह सामग्री {hindi_level} श्रेणी में है। {advice} कारण: {joined_reasons}"
    return f"This content is rated {level}. {joined_reasons}"


def plain_language_explanation(level: str, reasons: list[str], language: str) -> str:
    fallback = _fallback_explanation(level, reasons, language)
    if not config.ENABLE_LLM_EXPLANATIONS:
        return fallback
    prompt = (
        f"Explain this phishing scan result in simple {'Hindi' if language == 'hi' else 'English'} for a student or parent. "
        "Do not claim certainty, do not give security bypass advice, and keep it under 80 words. "
        f"Risk level: {level}. Evidence: {' '.join(reasons)}"
    )
    try:
        response = requests.post(
            config.OLLAMA_URL,
            json={"model": config.OLLAMA_MODEL, "prompt": prompt, "stream": False, "think": False},
            timeout=20,
        )
        response.raise_for_status()
        text = response.json().get("response", "").strip()
        return text or fallback
    except (requests.RequestException, ValueError, KeyError):
        return fallback

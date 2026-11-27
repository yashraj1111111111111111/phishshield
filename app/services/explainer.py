import requests

from app.config import ENABLE_LLM_EXPLANATIONS, OLLAMA_MODEL, OLLAMA_URL


def plain_language_explanation(level: str, reasons: list[str], language: str) -> str:
    fallback = f"This content is rated {level}. " + " ".join(reasons)
    if not ENABLE_LLM_EXPLANATIONS:
        return fallback
    prompt = (
        f"Explain this phishing scan result in simple {'Hindi' if language == 'hi' else 'English'} for a student or parent. "
        "Do not claim certainty, do not give security bypass advice, and keep it under 80 words. "
        f"Risk level: {level}. Evidence: {' '.join(reasons)}"
    )
    try:
        response = requests.post(OLLAMA_URL, json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False}, timeout=20)
        response.raise_for_status()
        return response.json().get("response", fallback).strip()
    except (requests.RequestException, ValueError, KeyError):
        return fallback

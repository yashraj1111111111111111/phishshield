import os

DATABASE_PATH = os.getenv("DATABASE_PATH", "database/phishshield.db")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen3.5:9b")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")
ENABLE_LLM_EXPLANATIONS = os.getenv("ENABLE_LLM_EXPLANATIONS", "false").lower() == "true"
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "10"))

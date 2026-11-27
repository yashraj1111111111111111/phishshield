import os

from dotenv import load_dotenv

load_dotenv()

DATABASE_PATH = os.getenv("DATABASE_PATH", "database/phishshield.db")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen3.5:9b")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")
ENABLE_LLM_EXPLANATIONS = os.getenv("ENABLE_LLM_EXPLANATIONS", "false").lower() == "true"
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "10"))
IP_HASH_SALT = os.getenv("IP_HASH_SALT", "phishshield-local-dev-salt")
TRUST_PROXY_HEADERS = os.getenv("TRUST_PROXY_HEADERS", "false").lower() == "true"
STORE_SCAN_CONTENT = os.getenv("STORE_SCAN_CONTENT", "false").lower() == "true"
SCAN_RETENTION_DAYS = int(os.getenv("SCAN_RETENTION_DAYS", "30"))

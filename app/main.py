from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from app.database.connection import initialize_database
from app.database.repository import save_scan
from app.detectors.scanner import scan
from app.services.abuse_protection import enforce_rate_limit
from app.services.explainer import plain_language_explanation


@asynccontextmanager
async def lifespan(_: FastAPI):
    initialize_database()
    yield


app = FastAPI(title="PhishShield API", version="0.1.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"], allow_credentials=False, allow_methods=["*"], allow_headers=["*"])


class ScanRequest(BaseModel):
    content: str = Field(min_length=3, max_length=5000)
    language: str = Field(default="en", pattern="^(en|hi)$")


class ScanResponse(BaseModel):
    scan_reference: str
    risk_score: int
    risk_level: str
    content_type: str
    reasons: list[str]
    explanation: str


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/scan", response_model=ScanResponse)
def create_scan(payload: ScanRequest, request: Request) -> ScanResponse:
    client_ip = request.client.host if request.client else "unknown"
    enforce_rate_limit(client_ip)
    result = scan(payload.content)
    reference = save_scan(payload.content, result.content_type, result.score, result.level, result.reasons, payload.language)
    explanation = plain_language_explanation(result.level, result.reasons, payload.language)
    return ScanResponse(scan_reference=reference, risk_score=result.score, risk_level=result.level, content_type=result.content_type, reasons=result.reasons, explanation=explanation)

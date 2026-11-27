from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from app import config
from app.database.connection import initialize_database
from app.services.scan_pipeline import run_scan_pipeline


@asynccontextmanager
async def lifespan(_: FastAPI):
    initialize_database()
    yield


app = FastAPI(title="PhishShield API", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ALLOW_ORIGINS,
    allow_origin_regex=config.CORS_ALLOW_ORIGIN_REGEX,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


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
    ml_probability: float | None = None
    campaign_detected: bool = False
    technical_details: dict[str, Any] = Field(default_factory=dict)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


def resolve_client_ip(request: Request) -> str:
    """Resolve client IP, trusting X-Forwarded-For only when TRUST_PROXY_HEADERS=true."""
    if config.TRUST_PROXY_HEADERS:
        forwarded_for = request.headers.get("x-forwarded-for", "")
        if forwarded_for:
            first_hop = forwarded_for.split(",", 1)[0].strip()
            if first_hop:
                return first_hop
    return request.client.host if request.client else "unknown"


@app.post("/api/scan", response_model=ScanResponse)
def create_scan(payload: ScanRequest, request: Request) -> ScanResponse:
    client_ip = resolve_client_ip(request)
    outcome = run_scan_pipeline(payload.content, payload.language, client_ip)
    return ScanResponse(
        scan_reference=outcome.scan_reference,
        risk_score=outcome.risk_score,
        risk_level=outcome.risk_level,
        content_type=outcome.content_type,
        reasons=outcome.reasons,
        explanation=outcome.explanation,
        ml_probability=outcome.ml_probability,
        campaign_detected=outcome.campaign_detected,
        technical_details=outcome.technical_details,
    )

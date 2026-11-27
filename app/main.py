from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from app.database.connection import initialize_database
from app.services.scan_pipeline import run_scan_pipeline


@asynccontextmanager
async def lifespan(_: FastAPI):
    initialize_database()
    yield


app = FastAPI(title="PhishShield API", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_origin_regex=r"^chrome-extension://.*$",
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


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/scan", response_model=ScanResponse)
def create_scan(payload: ScanRequest, request: Request) -> ScanResponse:
    client_ip = request.client.host if request.client else "unknown"
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
    )

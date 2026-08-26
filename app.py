import os
from typing import List, Optional
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl, Field

# Handle pipeline import safely to prevent IDE/Python path squiggles
try:
    from src.pipeline import PhishingDetectorPipeline
except ModuleNotFoundError:
    import sys
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from src.pipeline import PhishingDetectorPipeline

app = FastAPI(
    title="Phishing Detection API",
    description="Real-time phishing detection service using heuristic analysis and machine learning.",
    version="1.1.0",
)

# Configure CORS for local dev, Docker, and deployment previews (e.g. Vercel)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:8080",
        "http://127.0.0.1:8080",
        "http://localhost:3000",
    ],
    allow_origin_regex=r"https://.*\.vercel\.app",  # Matches Vercel preview & production deployments
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize pipeline instance
pipeline = PhishingDetectorPipeline()

# --- Request / Response Models ---

class URLRequest(BaseModel):
    url: str = Field(..., json_schema_extra={"example": "https://suspicious-login-attempt.com"})

class TextRequest(BaseModel):
    text: str = Field(..., json_schema_extra={"example": "Urgent: Your account has been suspended. Click here to verify."})

class BatchURLRequest(BaseModel):
    urls: List[str] = Field(..., min_length=1, max_length=50)

class PredictionRequest(BaseModel):
    url: Optional[str] = None
    text: Optional[str] = None

# --- Health Check Endpoints ---

@app.get("/", tags=["System"])
def read_root():
    return {
        "status": "online",
        "service": "Phishing Detection API",
        "version": "1.1.0"
    }

@app.get("/health", tags=["System"])
def health_check():
    return {"status": "healthy"}

# --- Inspection & Prediction Endpoints ---

@app.post("/predict", tags=["Detection"])
def predict(payload: PredictionRequest):
    """
    Unified endpoint supporting both URL scanning and text message analysis 
    matching frontend React client payloads.
    """
    target = payload.url or payload.text
    if not target or not target.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payload must contain a non-empty 'url' or 'text' field."
        )
    try:
        return pipeline.inspect_url(target.strip())
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error processing request: {str(e)}"
        )

@app.post("/analyze", tags=["Detection"])
@app.post("/api/v1/inspect", tags=["Detection"])
def inspect_url(payload: URLRequest):
    """Scan a single URL using heuristic analysis and ML models."""
    if not payload.url or not payload.url.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="URL string cannot be empty."
        )
    try:
        return pipeline.inspect_url(payload.url.strip())
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            detail=f"Error inspecting URL: {str(e)}"
        )

@app.post("/analyze/batch", tags=["Detection"])
def inspect_batch(payload: BatchURLRequest):
    """Scan multiple URLs in a single request (Max 50 URLs)."""
    results = []
    for raw_url in payload.urls:
        clean_url = raw_url.strip()
        if not clean_url:
            continue
        try:
            res = pipeline.inspect_url(clean_url)
            results.append({"url": clean_url, "result": res, "error": None})
        except Exception as e:
            results.append({"url": clean_url, "result": None, "error": str(e)})
            
    return {"processed": len(results), "results": results}
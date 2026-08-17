import os
import json
import logging
from contextlib import asynccontextmanager
from typing import List, Dict, Any, Optional

from fastapi import FastAPI, Depends, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, ConfigDict
from sqlalchemy.orm import Session
from sqlalchemy import func

from src.database import engine, Base, get_db
from src import models
from src.pipeline import PhishingDetectorPipeline

# Setup Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("phishing_api")

# Global Pipeline Reference
pipeline: Optional[PhishingDetectorPipeline] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager handling startup DB setup and model initialization."""
    global pipeline
    logger.info("Initializing Database tables...")
    Base.metadata.create_all(bind=engine)
    
    logger.info("Loading Phishing Detector Pipeline model artifacts...")
    try:
        pipeline = PhishingDetectorPipeline()
        logger.info("Pipeline loaded successfully.")
    except Exception as e:
        logger.warning(f"Failed to load pipeline artifacts on startup: {e}")
        pipeline = None
        
    yield
    
    logger.info("Shutting down Phishing Detection API service.")


app = FastAPI(
    title="Hybrid ML Phishing Detection API",
    version="1.1.0",
    description="Enterprise API engine combining Random Forest ML classification with configurable heuristic rules.",
    lifespan=lifespan,
)

# CORS Configuration - Dynamic Regex Support for Vercel & Local Dev
raw_origins = os.getenv(
    "ALLOWED_ORIGINS", 
    "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000"
)
origins = [origin.strip() for origin in raw_origins.split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins if "*" not in origins else ["*"],
    allow_origin_regex=r"https://.*\.vercel\.app",  # Matches all Vercel previews & production apps
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Pydantic Schemas ---

class URLInspectionRequest(BaseModel):
    url: str = Field(..., json_schema_extra={"example": "http://login-verification-secure-account.com/login.php"})

class BatchURLInspectionRequest(BaseModel):
    urls: List[str] = Field(..., max_length=100, json_schema_extra={"example": ["https://google.com", "http://suspicious-link.tk"]})

class RulesConfigModel(BaseModel):
    max_url_length: int = Field(default=75, ge=10, le=2000)
    max_special_chars: int = Field(default=10, ge=0, le=100)
    max_subdomains: int = Field(default=3, ge=0, le=20)
    max_entropy: float = Field(default=4.5, ge=0.0, le=8.0)
    block_ip_hostnames: bool = Field(default=True)
    flag_sensitive_keywords: bool = Field(default=True)

    model_config = ConfigDict(from_attributes=True)

class InspectionResultResponse(BaseModel):
    url: str
    verdict: str
    ml_probability: float
    heuristic_flags_count: int
    fired_rules: Any

class ScanLogResponse(BaseModel):
    id: int
    timestamp: str
    url: str
    verdict: str
    ml_probability: Optional[float] = 0.0
    heuristic_flags_count: int
    fired_rules: Any

class TelemetryStatsResponse(BaseModel):
    total_scans: int
    phishing_count: int
    legitimate_count: int
    suspicious_count: int
    phishing_ratio_percentage: float
    avg_ml_probability: float


# --- Helper Functions ---

def get_or_create_config(db: Session) -> models.ConfigRule:
    """Retrieve existing heuristic config or populate default row (ID: 1)."""
    config = db.query(models.ConfigRule).filter(models.ConfigRule.id == 1).first()
    if not config:
        config = models.ConfigRule(id=1)
        db.add(config)
        db.commit()
        db.refresh(config)
    return config

def sync_pipeline_config(config: models.ConfigRule):
    """Inject active DB config parameters directly into the pipeline engine."""
    if pipeline and hasattr(pipeline, "update_heuristic_config"):
        pipeline.update_heuristic_config({
            "max_url_length": config.max_url_length,
            "max_special_chars": config.max_special_chars,
            "max_subdomains": config.max_subdomains,
            "max_entropy": config.max_entropy,
            "block_ip_hostnames": config.block_ip_hostnames,
            "flag_sensitive_keywords": config.flag_sensitive_keywords,
        })

def log_inspection_result(result: Dict[str, Any], db: Session) -> models.InspectionLog:
    """Persist inspection run outcomes into database logs safely using model instantiator."""
    # Convert dictionaries to JSON strings if database column expects text/string JSON
    fired_rules = result.get("fired_rules", [])
    if isinstance(fired_rules, (list, dict)):
        fired_rules_str = json.dumps(fired_rules)
    else:
        fired_rules_str = str(fired_rules)

    flags_count = result.get("heuristic_flags_count") or result.get("flags_count") or 0

    log_entry = models.InspectionLog(
        url=result.get("url"),
        verdict=result.get("verdict"),
        ml_probability=result.get("ml_probability", 0.0),
        flags_count=flags_count,
        fired_rules=fired_rules_str
    )
    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)
    return log_entry


# --- System Health & Readiness ---

@app.get("/health", status_code=status.HTTP_200_OK, tags=["System Integrity"])
@app.get("/", status_code=status.HTTP_200_OK, tags=["System Integrity"])
def health_check():
    """Health check endpoint used by Docker & Render target groups."""
    return {
        "status": "healthy" if pipeline is not None else "degraded",
        "model_loaded": pipeline is not None
    }

@app.post("/api/v1/model/reload", tags=["System Integrity"])
def reload_model():
    """Hot-reload pipeline model artifacts without restarting container."""
    global pipeline
    try:
        pipeline = PhishingDetectorPipeline()
        return {"status": "success", "message": "Pipeline and model weights reloaded successfully."}
    except Exception as e:
        logger.error(f"Error reloading model: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to reload model artifact: {str(e)}"
        )


# --- Configuration Rules ---

@app.get("/api/v1/config", response_model=RulesConfigModel, tags=["Configuration Rules"])
def get_config(db: Session = Depends(get_db)):
    """Fetch current heuristic thresholds and rules."""
    return get_or_create_config(db)

@app.put("/api/v1/config", response_model=RulesConfigModel, tags=["Configuration Rules"])
def update_config(new_config: RulesConfigModel, db: Session = Depends(get_db)):
    """Update heuristic parameters and sync instantly with active model engine."""
    config = get_or_create_config(db)
    for key, value in new_config.model_dump().items():
        setattr(config, key, value)
    
    db.commit()
    db.refresh(config)
    
    sync_pipeline_config(config)
    return config


# --- Inspection Endpoints ---

@app.post("/api/v1/inspect", response_model=InspectionResultResponse, tags=["Inspection Engine"])
@app.post("/predict", response_model=InspectionResultResponse, tags=["Inspection Engine"])
def inspect_url(payload: URLInspectionRequest, db: Session = Depends(get_db)):
    """Analyze a single target URL using hybrid ML classification & heuristic rules."""
    if not pipeline:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Phishing detection pipeline model is not initialized or trained."
        )
    
    config = get_or_create_config(db)
    sync_pipeline_config(config)

    try:
        result = pipeline.inspect_url(payload.url)
        
        # Ensure return dict contains standardized keys expected by Pydantic response
        if "heuristic_flags_count" not in result and "flags_count" in result:
            result["heuristic_flags_count"] = result["flags_count"]

        log_inspection_result(result, db)
        return result
    except Exception as e:
        logger.error(f"Inspection failed for URL {payload.url}: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Could not inspect provided URL: {str(e)}"
        )

@app.post("/api/v1/inspect/batch", response_model=List[InspectionResultResponse], tags=["Inspection Engine"])
@app.post("/predict/batch", response_model=List[InspectionResultResponse], tags=["Inspection Engine"])
def inspect_urls_batch(payload: BatchURLInspectionRequest, db: Session = Depends(get_db)):
    """Analyze up to 100 URLs in a single batch transaction."""
    if not pipeline:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Phishing detection pipeline model is not initialized or trained."
        )
    
    config = get_or_create_config(db)
    sync_pipeline_config(config)

    try:
        results = pipeline.inspect_urls_batch(payload.urls)
        for res in results:
            if "heuristic_flags_count" not in res and "flags_count" in res:
                res["heuristic_flags_count"] = res["flags_count"]
            log_inspection_result(res, db)
        return results
    except Exception as e:
        logger.error(f"Batch URL inspection failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Could not process batch URL inspection: {str(e)}"
        )


# --- Telemetry & Analytics ---

@app.get("/api/v1/telemetry", response_model=List[ScanLogResponse], tags=["Telemetry & Analytics"])
def get_telemetry(
    limit: int = Query(default=50, ge=1, le=500),
    verdict_filter: Optional[str] = Query(default=None, pattern="^(PHISHING|LEGITIMATE|BENIGN|SUSPICIOUS|BLOCKED)$"),
    db: Session = Depends(get_db)
):
    """Retrieve raw historical scan audit logs with optional verdict filtering."""
    query = db.query(models.InspectionLog)
    
    if verdict_filter:
        query = query.filter(models.InspectionLog.verdict == verdict_filter)
        
    logs = query.order_by(models.InspectionLog.created_at.desc()).limit(limit).all()
    
    output = []
    for log in logs:
        fired_rules = log.fired_rules or []
        if isinstance(fired_rules, str):
            try:
                fired_rules = json.loads(fired_rules)
            except Exception:
                fired_rules = [fired_rules]

        ts_val = log.created_at.isoformat() if hasattr(log.created_at, "isoformat") else str(log.created_at)
        flags_count = getattr(log, "heuristic_flags_count", None) or getattr(log, "flags_count", 0)

        output.append({
            "id": log.id,
            "timestamp": ts_val,
            "url": log.url,
            "verdict": log.verdict,
            "ml_probability": log.ml_probability or 0.0,
            "heuristic_flags_count": flags_count,
            "fired_rules": fired_rules
        })
    return output

@app.get("/api/v1/telemetry/stats", response_model=TelemetryStatsResponse, tags=["Telemetry & Analytics"])
def get_telemetry_stats(db: Session = Depends(get_db)):
    """Calculate aggregate telemetry metrics across all scanned target URLs."""
    total_scans = db.query(func.count(models.InspectionLog.id)).scalar() or 0
    
    if total_scans == 0:
        return {
            "total_scans": 0,
            "phishing_count": 0,
            "legitimate_count": 0,
            "suspicious_count": 0,
            "phishing_ratio_percentage": 0.0,
            "avg_ml_probability": 0.0,
        }

    phishing_count = db.query(func.count(models.InspectionLog.id)).filter(
        models.InspectionLog.verdict.in_(["PHISHING", "BLOCKED"])
    ).scalar() or 0
    
    legitimate_count = db.query(func.count(models.InspectionLog.id)).filter(
        models.InspectionLog.verdict.in_(["LEGITIMATE", "BENIGN"])
    ).scalar() or 0
    
    suspicious_count = db.query(func.count(models.InspectionLog.id)).filter(
        models.InspectionLog.verdict == "SUSPICIOUS"
    ).scalar() or 0
    
    avg_ml_prob = db.query(func.avg(models.InspectionLog.ml_probability)).scalar() or 0.0
    phishing_ratio = round((phishing_count / total_scans) * 100, 2)

    return {
        "total_scans": total_scans,
        "phishing_count": phishing_count,
        "legitimate_count": legitimate_count,
        "suspicious_count": suspicious_count,
        "phishing_ratio_percentage": phishing_ratio,
        "avg_ml_probability": round(float(avg_ml_prob), 4),
    }
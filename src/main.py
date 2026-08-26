"""
API application entry point and CLI engine for the Phishing Detection System.
Implements API v1 routes, lifespan database management, CLI functionality,
and fault-tolerant database logging inside endpoint handlers.
"""

import argparse
import asyncio
import json
import logging
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from src.database import (
    check_db_health,
    get_db,
    get_scan_history,
    get_telemetry_stats,
    init_db,
    log_scan,
)
from src.pipeline import PhishingDetectorPipeline
from src.schemas import (
    BatchInspectRequest,
    HealthCheckResponse,
    InspectRequest,
    ScanResponse,
    TelemetryResponse,
)

logger = logging.getLogger(__name__)

# Global Pipeline Instances
pipeline: Optional[PhishingDetectorPipeline] = None
_pipeline_instance: Optional[PhishingDetectorPipeline] = None


@asynccontextmanager
async def lifespan(app_instance: FastAPI):
    """FastAPI Lifespan Handler for Startup and Shutdown tasks."""
    global pipeline, _pipeline_instance
    try:
        await asyncio.to_thread(init_db)
    except Exception as e:
        logger.warning(f"⚠️ DB Initialization Warning during startup: {e}")

    try:
        pipeline = await asyncio.to_thread(PhishingDetectorPipeline)
        _pipeline_instance = pipeline
    except Exception as e:
        logger.error(f"⚠️ Pipeline initialization deferred or failed: {e}")

    yield


app = FastAPI(
    title="Phishing Detection Hybrid System API",
    description="REST API & Machine Learning engine combining statistical models with heuristic rules.",
    version="1.1.0",
    lifespan=lifespan,
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =====================================================================
# Exception Handlers (Guarantees HTTP 500 on Database Errors)
# =====================================================================

@app.exception_handler(SQLAlchemyError)
async def sqlalchemy_exception_handler(request: Request, exc: SQLAlchemyError):
    """
    Catches any unhandled SQLAlchemy or database driver exceptions mid-request
    and returns a standard HTTP 500 response, avoiding silent HTTP 200 fallbacks.
    """
    logger.error(f"Database error executing request {request.method} {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": f"Database transaction error: {str(exc)}"},
    )


# API v1 Router Definition
api_router = APIRouter(prefix="/api/v1")


def get_pipeline() -> PhishingDetectorPipeline:
    """Dependency helper to guarantee an active pipeline instance."""
    global pipeline, _pipeline_instance
    if _pipeline_instance is not None:
        return _pipeline_instance
    if pipeline is None:
        pipeline = PhishingDetectorPipeline()
        _pipeline_instance = pipeline
    return pipeline


def _format_scan_response(result: dict, fallback_url: str) -> ScanResponse:
    """Helper mapping pipeline raw output dictionaries directly to ScanResponse schema."""
    raw_conf = result.get("confidence")
    if raw_conf is None:
        raw_conf = result.get("confidence_score", result.get("risk_score", 0.0))

    try:
        confidence_score = float(raw_conf)
        if confidence_score > 1.0 and "confidence" in result:
            confidence_score = float(result["confidence"])
    except (ValueError, TypeError):
        confidence_score = 0.0

    raw_model = result.get("model_score")
    if raw_model is None:
        raw_model = result.get("model_prediction", result.get("confidence", 0.0))

    try:
        model_pred = float(raw_model)
        if model_pred > 1.0:
            model_pred /= 100.0
    except (ValueError, TypeError):
        model_pred = 0.0

    try:
        risk_score = float(
            result.get(
                "risk_score",
                result.get("score", result.get("confidence_score", confidence_score)),
            )
        )
    except (ValueError, TypeError):
        risk_score = 0.0

    timestamp = str(
        result.get("scanned_at")
        or result.get("scan_timestamp")
        or datetime.now(timezone.utc).isoformat()
    )

    return ScanResponse(
        url=result.get("url", fallback_url),
        prediction=str(result.get("prediction", "legitimate")),
        is_phishing=bool(result.get("is_phishing", False)),
        risk_score=risk_score,
        confidence_score=confidence_score,
        risk_level=str(result.get("risk_level", "LOW")).upper(),
        heuristics_triggered=result.get("heuristics_triggered", []),
        model_prediction=model_pred,
        scan_timestamp=timestamp,
        scanned_at=timestamp,
    )


# =====================================================================
# API Endpoints
# =====================================================================

@app.get("/", tags=["Root"])
async def read_root():
    return {
        "status": "online",
        "system": "Phishing Detection Hybrid System API",
        "version": "1.1.0",
        "docs_url": "/docs",
    }


@api_router.get("/health", response_model=HealthCheckResponse, tags=["Health"])
async def health_check(db: Session = Depends(get_db)):
    """Health check endpoint to verify database connectivity and model status."""
    try:
        db_ok = await asyncio.to_thread(check_db_health, session=db)
    except Exception as e:
        logger.error(f"Health check DB ping failed: {e}")
        db_ok = False

    active_pipeline = _pipeline_instance or pipeline

    return HealthCheckResponse(
        status="healthy" if db_ok else "degraded",
        version="1.1.0",
        database_connected=db_ok,
        model_loaded=active_pipeline is not None and getattr(active_pipeline, "model", None) is not None,
    )


@api_router.post("/scan", response_model=ScanResponse, tags=["Analysis"])
@api_router.post("/inspect", response_model=ScanResponse, tags=["Analysis"])
async def inspect_single_url(payload: InspectRequest, db: Session = Depends(get_db)):
    """Analyze a single URL using hybrid ML and heuristic evaluation."""
    target_url = payload.url.strip() if payload.url else ""
    if not target_url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The 'url' field cannot be empty.",
        )
    
    detector = get_pipeline()
    result = await asyncio.to_thread(detector.inspect_url, target_url)

    # Persist scan result to DB safely. Logs failure without breaking the user response.
    try:
        await asyncio.to_thread(log_scan, result, session=db)
    except Exception as db_err:
        if hasattr(db, "rollback"):
            db.rollback()
        logger.error(f"Failed to persist scan result for '{target_url}': {db_err}")

    return _format_scan_response(result, target_url)


@api_router.post("/scan/batch", response_model=List[ScanResponse], tags=["Analysis"])
@api_router.post("/inspect/batch", response_model=List[ScanResponse], tags=["Analysis"])
async def inspect_batch_urls(payload: BatchInspectRequest, db: Session = Depends(get_db)):
    """Batch analyze multiple URLs asynchronously using hybrid ML and heuristic evaluation."""
    if not payload.urls:
        return []

    detector = get_pipeline()
    clean_urls = [u.strip() for u in payload.urls if isinstance(u, str) and u.strip()]

    if not clean_urls:
        return []

    if hasattr(detector, "analyze_batch_async"):
        results = await detector.analyze_batch_async(clean_urls)
    elif hasattr(detector, "inspect_batch_async"):
        results = await detector.inspect_batch_async(clean_urls)
    else:
        results = await asyncio.to_thread(detector.inspect_batch, clean_urls)

    formatted_responses = []
    for target, res in zip(clean_urls, results):
        try:
            await asyncio.to_thread(log_scan, res, session=db)
        except Exception as db_err:
            if hasattr(db, "rollback"):
                db.rollback()
            logger.error(f"Failed to persist batch scan item for '{target}': {db_err}")

        formatted_responses.append(_format_scan_response(res, target))

    return formatted_responses


@api_router.get("/history", tags=["Telemetry"])
async def fetch_scan_history(
    limit: int = Query(default=50, ge=1, le=500),
    db: Session = Depends(get_db),
):
    """Retrieve recent scan history for dashboards."""
    try:
        return await asyncio.to_thread(get_scan_history, limit=limit, session=db)
    except SQLAlchemyError as db_err:
        db.rollback()
        logger.error(f"Database failure while querying scan history: {db_err}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to query database history: {str(db_err)}",
        )


@api_router.get("/telemetry", response_model=TelemetryResponse, tags=["Telemetry"])
@api_router.get("/stats", response_model=TelemetryResponse, tags=["Telemetry"])
async def get_stats(db: Session = Depends(get_db)):
    """Retrieve aggregated telemetry statistics."""
    try:
        stats = await asyncio.to_thread(get_telemetry_stats, session=db)
        return TelemetryResponse(
            total_scans=stats.get("total_scans", 0),
            phishing_detected=stats.get("phishing_detected", stats.get("total_phishing", 0)),
            clean_urls=stats.get("clean_urls", stats.get("total_legitimate", 0)),
            top_heuristics=stats.get("top_heuristics", {}),
        )
    except SQLAlchemyError as db_err:
        db.rollback()
        logger.error(f"Database error while querying telemetry stats: {db_err}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Telemetry query transaction error: {str(db_err)}",
        )


# Mount the API v1 router to FastAPI app
app.include_router(api_router)

# Mount un-prefixed routes for backward compatibility / root endpoints
app.add_api_route("/health", health_check, response_model=HealthCheckResponse, tags=["Health"], include_in_schema=False)
app.add_api_route("/inspect", inspect_single_url, methods=["POST"], response_model=ScanResponse, tags=["Analysis"], include_in_schema=False)
app.add_api_route("/inspect/batch", inspect_batch_urls, methods=["POST"], response_model=List[ScanResponse], tags=["Analysis"], include_in_schema=False)
app.add_api_route("/history", fetch_scan_history, methods=["GET"], tags=["Telemetry"], include_in_schema=False)
app.add_api_route("/telemetry", get_stats, methods=["GET"], response_model=TelemetryResponse, tags=["Telemetry"], include_in_schema=False)
app.add_api_route("/stats", get_stats, methods=["GET"], response_model=TelemetryResponse, tags=["Telemetry"], include_in_schema=False)


# =====================================================================
# Terminal CLI Engine
# =====================================================================

COLORS = {
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
    "GREEN": "\033[92m",
    "YELLOW": "\033[93m",
    "ORANGE": "\033[38;5;208m",
    "RED": "\033[91m",
    "CYAN": "\033[96m",
    "GRAY": "\033[90m",
}


def get_risk_color(risk_level: str) -> str:
    level = str(risk_level).upper()
    if "LOW" in level or "SAFE" in level:
        return f"{COLORS['GREEN']}{level}{COLORS['RESET']}"
    if "MEDIUM" in level:
        return f"{COLORS['YELLOW']}{level}{COLORS['RESET']}"
    if "HIGH" in level:
        return f"{COLORS['ORANGE']}{level}{COLORS['RESET']}"
    if "CRITICAL" in level or "PHISHING" in level:
        return f"{COLORS['RED']}{level}{COLORS['RESET']}"
    return f"{COLORS['GRAY']}{level}{COLORS['RESET']}"


def print_banner():
    print(f"{COLORS['CYAN']}{'=' * 60}{COLORS['RESET']}")
    print(f" {COLORS['BOLD']}🛡️  PHISHING DETECTION HYBRID SYSTEM — CLI ENGINE{COLORS['RESET']}")
    print(f"{COLORS['CYAN']}{'=' * 60}{COLORS['RESET']}")


def print_result_card(result: dict, show_features: bool = False):
    url = result.get("url", "N/A")
    pred = str(result.get("prediction", "UNKNOWN")).upper()
    score = result.get("risk_score", result.get("confidence_score", 0))

    try:
        conf = float(result.get("model_score", result.get("confidence", 0.0))) * 100.0
    except (ValueError, TypeError):
        conf = 0.0

    risk_lvl = result.get("risk_level", "UNKNOWN")

    pred_colored = (
        f"{COLORS['RED']}{pred}{COLORS['RESET']}"
        if "PHISH" in pred
        else f"{COLORS['GREEN']}{pred}{COLORS['RESET']}"
    )

    print(f"\n🔍 Target URL:  {COLORS['BOLD']}{url}{COLORS['RESET']}")
    print(f"📊 Prediction:  {pred_colored}")
    print(f"⚠️  Risk Level:  {get_risk_color(risk_lvl)} ({score}/100 Risk Score)")
    print(f"🎯 ML Model:    {conf:.1f}% Probability")

    print("\n🚨 Heuristics Triggered:")
    heuristics = result.get("heuristics_triggered", [])
    if heuristics:
        for h in heuristics:
            rule_str = h["rule"] if isinstance(h, dict) and "rule" in h else str(h)
            print(f"   • [{COLORS['RED']}TRIGGER{COLORS['RESET']}] {rule_str}")
    else:
        print(f"   • {COLORS['GREEN']}None (Clean scan){COLORS['RESET']}")

    if show_features and result.get("features"):
        print("\n⚙️ Feature Breakdown:")
        for key, val in result["features"].items():
            print(f"   - {key:<22}: {val}")

    print(f"{COLORS['GRAY']}{'-' * 60}{COLORS['RESET']}")


def run_interactive_mode(pipeline_inst: PhishingDetectorPipeline, verbose: bool = False):
    print_banner()
    print("Type 'exit' or 'q' to quit interactive shell.\n")
    while True:
        try:
            url = input(f"{COLORS['BOLD']}Enter URL to scan > {COLORS['RESET']}").strip()
            if not url:
                continue
            if url.lower() in ("exit", "q", "quit"):
                print("Exiting CLI scanner.")
                break

            result = pipeline_inst.inspect_url(url)
            try:
                log_scan(result)
            except Exception as db_err:
                logger.warning(f"Interactive scan logging failed: {db_err}")

            print_result_card(result, show_features=verbose)
        except (KeyboardInterrupt, EOFError):
            print("\nExiting interactive mode.")
            break
        except Exception as e:
            print(f"❌ Error inspecting URL: {e}")
            break  # Break out on runtime errors during test execution to prevent infinite loop


def run_file_batch(
    filepath: str,
    pipeline_inst: PhishingDetectorPipeline,
    verbose: bool = False,
    json_output: bool = False,
):
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        if not urls:
            print(f"⚠️ Warning: No valid URLs found in '{filepath}'")
            return

        print(f"\n📂 Loaded {len(urls)} URLs from {filepath}. Scanning...\n")

        results = pipeline_inst.inspect_batch(urls)

        for res in results:
            try:
                log_scan(res)
            except Exception as db_err:
                logger.warning(f"Batch scan logging failed: {db_err}")

            if json_output:
                print(json.dumps(res, indent=2))
            else:
                print_result_card(res, show_features=verbose)

    except FileNotFoundError:
        print(f"❌ Error: File not found at '{filepath}'")
    except Exception as e:
        print(f"❌ Error processing batch file: {e}")


def main(sys_args: Optional[List[str]] = None):
    try:
        init_db()
    except Exception as e:
        print(f"⚠️ Warning: Database initialization failed ({e}). Proceeding without persistence.")

    parser = argparse.ArgumentParser(description="Phishing Detection System CLI Tool")
    parser.add_argument("url", nargs="?", help="Single URL to analyze")
    parser.add_argument("-f", "--file", help="Path to text file containing URLs (one per line)")
    parser.add_argument("-i", "--interactive", action="store_true", help="Launch interactive terminal scan shell")
    parser.add_argument("-j", "--json", action="store_true", help="Output raw JSON analysis")
    parser.add_argument("-v", "--verbose", action="store_true", help="Display extracted lexical feature values")
    parser.add_argument("-s", "--stats", action="store_true", help="View database telemetry statistics")

    args = parser.parse_args(sys_args)

    try:
        detector = get_pipeline()
    except Exception as e:
        print(f"❌ Error: Could not initialize detection pipeline ({e})")
        return

    if args.stats:
        try:
            stats_data = get_telemetry_stats()
            print_banner()
            print(f"\n{COLORS['BOLD']}📈 DATABASE TELEMETRY STATS:{COLORS['RESET']}")
            print(f" Total Scans Processed : {stats_data.get('total_scans', 0)}")
            print(f" Phishing Detected     : {stats_data.get('phishing_detected', stats_data.get('total_phishing', 0))}")
            print(f" Legitimate Scanned    : {stats_data.get('clean_urls', stats_data.get('total_legitimate', 0))}")
            print(f" Phishing Rate         : {stats_data.get('phishing_ratio', stats_data.get('phishing_rate_percentage', 0.0))}%\n")
        except Exception as e:
            print(f"❌ Failed to fetch telemetry stats: {e}")
        return

    if args.interactive:
        run_interactive_mode(detector, verbose=args.verbose)
        return

    if args.file:
        run_file_batch(args.file, detector, verbose=args.verbose, json_output=args.json)
        return

    target_url = args.url if args.url else "http://login-verify-account-security-update.com"
    if not args.url and not args.json:
        print_banner()
        print(f"{COLORS['YELLOW']}No URL provided. Scanning default test target...{COLORS['RESET']}")

    try:
        result = detector.inspect_url(target_url)
        try:
            log_scan(result)
        except Exception as db_err:
            logger.warning(f"CLI scan persistence failed: {db_err}")

        if args.json:
            print(json.dumps(result, indent=2))
        else:
            if args.url:
                print_banner()
            print_result_card(result, show_features=args.verbose)
    except Exception as e:
        print(f"❌ Error analyzing URL '{target_url}': {e}")


if __name__ == "__main__":
    main()
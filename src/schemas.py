from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, ConfigDict, Field


class HeuristicDetail(BaseModel):
    rule: str = Field(
        ...,
        description="Name or ID of the triggered rule",
        json_schema_extra={"example": "IP_ADDRESS_IN_HOST"},
    )
    description: Optional[str] = Field(
        None,
        description="Explanation of why rule triggered",
        json_schema_extra={"example": "Host uses an IP address instead of domain"},
    )
    score_impact: Optional[float] = Field(
        None,
        description="Point increase to risk score",
        json_schema_extra={"example": 25.0},
    )


class InspectRequest(BaseModel):
    url: str = Field(
        ...,
        description="Target URL to inspect for phishing indicators.",
        json_schema_extra={"example": "http://login-verify-account-security-update.com"},
    )


class BatchInspectRequest(BaseModel):
    urls: List[str] = Field(
        ...,
        min_length=1,
        description="List of target URLs to batch inspect.",
        json_schema_extra={"example": ["https://google.com", "http://login-paypal-verify.com"]},
    )


class ScanRequest(BaseModel):
    url: str = Field(
        ...,
        description="URL to analyze for phishing threats",
        json_schema_extra={"example": "https://suspicious-login-portal.com/update"},
    )


class ScanResponse(BaseModel):
    url: str = Field(
        ...,
        description="Target URL that was evaluated",
        json_schema_extra={"example": "https://suspicious-login-portal.com/update"},
    )
    is_phishing: bool = Field(
        ...,
        description="True if URL exceeds threat threshold",
        json_schema_extra={"example": True},
    )
    confidence: Optional[float] = Field(
        None,
        ge=0.0,
        le=1.0,
        description="ML model confidence / probability score (0.0 to 1.0)",
        json_schema_extra={"example": 0.875},
    )
    confidence_score: Optional[float] = Field(
        None,
        description="Confidence score alias",
        json_schema_extra={"example": 0.875},
    )
    phishing_probability: Optional[float] = Field(
        None,
        ge=0.0,
        le=1.0,
        description="Aggregated risk probability (0.0 to 1.0)",
        json_schema_extra={"example": 0.875},
    )
    risk_score: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description="Composite threat score scaled between 0.0 and 100.0",
        json_schema_extra={"example": 87.5},
    )
    risk_level: str = Field(
        ...,
        description="Threat classification tier (LOW, MEDIUM, HIGH, CRITICAL)",
        json_schema_extra={"example": "CRITICAL"},
    )
    prediction: Optional[str] = Field(
        "LEGITIMATE",
        description="Categorical output: LEGITIMATE or PHISHING",
        json_schema_extra={"example": "PHISHING"},
    )
    ml_probability: Optional[float] = Field(
        None,
        ge=0.0,
        le=1.0,
        description="Raw ML model output probability",
        json_schema_extra={"example": 0.92},
    )
    model_prediction: Optional[float] = Field(
        None,
        description="Legacy alias for ML model output probability",
        json_schema_extra={"example": 0.92},
    )
    heuristic_score: Optional[float] = Field(
        0.0,
        ge=0.0,
        le=100.0,
        description="Raw heuristic rules score contribution",
        json_schema_extra={"example": 45.0},
    )
    heuristics_triggered: List[Union[str, HeuristicDetail]] = Field(
        default_factory=list,
        description="List of triggered rules or detailed objects",
    )
    triggered_rules: List[str] = Field(
        default_factory=list,
        description="List of rule IDs triggered during analysis",
    )
    features: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="Dictionary of raw extracted URL features",
    )
    status: str = Field(
        "success",
        description="Execution state of analysis (success/error)",
        json_schema_extra={"example": "success"},
    )
    message: Optional[str] = Field(
        None,
        description="Optional status or error diagnostic message",
    )
    scan_timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="UTC timestamp of the scan in ISO 8601 format",
        json_schema_extra={"example": "2026-08-21T13:58:00Z"},
    )


class BatchScanResponse(BaseModel):
    results: List[ScanResponse] = Field(
        default_factory=list,
        description="List of analysis results for submitted URLs",
    )
    total_processed: int = Field(
        ...,
        ge=0,
        description="Total count of processed URLs in batch",
        json_schema_extra={"example": 2},
    )


class TelemetryResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    total_scans: int = Field(
        ...,
        ge=0,
        description="Total URLs analyzed across system lifespan",
        json_schema_extra={"example": 1250},
    )
    phishing_detected: int = Field(
        ...,
        ge=0,
        alias="phishing_urls",
        description="Total confirmed phishing URLs detected",
        json_schema_extra={"example": 320},
    )
    clean_urls: int = Field(
        ...,
        ge=0,
        description="Total clean/legitimate URLs processed",
        json_schema_extra={"example": 930},
    )
    average_risk_score: Optional[float] = Field(
        0.0,
        ge=0.0,
        le=100.0,
        description="Mean risk score across all processed scans",
        json_schema_extra={"example": 24.5},
    )
    phishing_rate_percentage: Optional[float] = Field(
        0.0,
        ge=0.0,
        le=100.0,
        description="Percentage ratio of phishing threats to total scans",
        json_schema_extra={"example": 25.6},
    )
    top_heuristics: Dict[str, int] = Field(
        default_factory=dict,
        description="Frequency count of triggered rules",
        json_schema_extra={"example": {"IP_ADDRESS_IN_HOST": 142, "SUSPICIOUS_TLD": 98}},
    )


class HealthCheckResponse(BaseModel):
    status: str = Field("ok", json_schema_extra={"example": "ok"})
    version: str = Field("1.0.0", json_schema_extra={"example": "1.0.0"})
    database_connected: bool = Field(True)
    model_loaded: bool = Field(True)
import datetime
from datetime import timezone
from urllib.parse import urlparse
from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    Boolean,
    DateTime,
    Text,
    JSON,
    ForeignKey,
    Index,
)
from sqlalchemy.orm import relationship
from src.database import Base


def utc_now() -> datetime.datetime:
    """Helper returning timezone-aware UTC datetime."""
    return datetime.datetime.now(timezone.utc)


# --- DYNAMIC CONFIGURATION & WHITELIST MODELS ---

class ConfigRule(Base):
    """
    Stores system runtime settings, detection thresholds, and feature flags.
    Allows adjusting heuristic parameters dynamically without restarting the API.
    """
    __tablename__ = "config_rules"

    id = Column(Integer, primary_key=True, index=True, default=1)
    max_url_length = Column(Integer, nullable=False, default=75)
    max_special_chars = Column(Integer, nullable=False, default=10)
    max_subdomains = Column(Integer, nullable=False, default=3)
    max_entropy = Column(Float, nullable=False, default=4.5)
    
    # Feature Toggles
    block_ip_hostnames = Column(Boolean, nullable=False, default=True)
    flag_sensitive_keywords = Column(Boolean, nullable=False, default=True)
    flag_brand_spoofing = Column(Boolean, nullable=False, default=True)
    flag_non_standard_ports = Column(Boolean, nullable=False, default=True)
    flag_suspicious_tlds = Column(Boolean, nullable=False, default=True)

    # Auditing
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
    )


class WhitelistDomain(Base):
    """
    Stores custom whitelisted domains managed dynamically via administrative APIs.
    """
    __tablename__ = "whitelist_domains"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String(255), unique=True, index=True, nullable=False)
    description = Column(String(255), nullable=True)
    added_by = Column(String(100), nullable=True, default="admin")
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)


# --- THREAT & INSPECTION LOGGING MODELS ---

class InspectionLog(Base):
    """
    Audit record for every URL evaluation performed by the hybrid engine.
    """
    __tablename__ = "inspection_logs"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(Text, nullable=False)
    domain = Column(String(255), index=True, nullable=False)
    
    # Verdict Results (BENIGN, SUSPICIOUS, PHISHING, BLOCKED)
    verdict = Column(String(50), index=True, nullable=False)
    is_phishing = Column(Boolean, index=True, nullable=False)
    risk_score = Column(Float, nullable=False, default=0.0)
    
    # Machine Learning Output
    ml_probability = Column(Float, nullable=True)
    ml_model_version = Column(String(50), nullable=True, default="v1.0")
    
    # Heuristic Output
    flags_count = Column(Integer, nullable=False, default=0)
    override_verdict = Column(String(50), nullable=True)
    fired_rules = Column(JSON, nullable=True, default=list)  # Serialized list of triggered rule names
    
    # Performance & Timing
    execution_time_ms = Column(Float, nullable=True)
    client_ip = Column(String(45), nullable=True)  # Supports IPv4 and IPv6
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, index=True)

    def __init__(self, **kwargs):
        # 1. Alias mapping: map heuristic_flags_count to flags_count column
        if "heuristic_flags_count" in kwargs and "flags_count" not in kwargs:
            kwargs["flags_count"] = kwargs.pop("heuristic_flags_count")

        # 2. Extract domain automatically from URL if missing or None
        if not kwargs.get("domain") and kwargs.get("url"):
            try:
                parsed = urlparse(kwargs["url"])
                # Extract netloc or path segment if scheme is absent
                extracted_domain = parsed.netloc or parsed.path.split("/")[0]
                kwargs["domain"] = extracted_domain.split(":")[0]  # Strip port if present
            except Exception:
                kwargs["domain"] = "unknown"

        # Fallback safeguard against NOT NULL constraints on domain
        if not kwargs.get("domain"):
            kwargs["domain"] = "unknown"

        # 3. Derive is_phishing boolean if missing or None
        if kwargs.get("is_phishing") is None:
            verdict_val = str(kwargs.get("verdict", "")).upper()
            kwargs["is_phishing"] = verdict_val in ("PHISHING", "BLOCKED")

        # 4. Filter out any unmapped dictionary keys returned by the pipeline
        valid_columns = {column.name for column in self.__table__.columns}
        filtered_kwargs = {k: v for k, v in kwargs.items() if k in valid_columns}

        super().__init__(**filtered_kwargs)

    # Legacy field alias for tests querying 'timestamp' directly
    @property
    def timestamp(self):
        return self.created_at

    # Legacy alias property so inspection_log.heuristic_flags_count works downstream
    @property
    def heuristic_flags_count(self):
        return self.flags_count

    @heuristic_flags_count.setter
    def heuristic_flags_count(self, value):
        self.flags_count = value

    # Relationship to extracted feature vector
    extracted_features = relationship(
        "ExtractedFeature",
        back_populates="inspection_log",
        uselist=False,
        cascade="all, delete-orphan",
    )


class ExtractedFeature(Base):
    """
    Detailed vector of extracted numerical and categorical features for an inspected URL.
    Used for offline retraining and model drift analytics.
    """
    __tablename__ = "extracted_features"

    id = Column(Integer, primary_key=True, index=True)
    inspection_id = Column(
        Integer,
        ForeignKey("inspection_logs.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
    )
    
    # Structural features
    url_length = Column(Integer, nullable=False)
    domain_length = Column(Integer, nullable=False)
    subdomain_count = Column(Integer, nullable=False)
    special_char_count = Column(Integer, nullable=False)
    entropy = Column(Float, nullable=False)
    
    # Binary flags
    has_ip = Column(Integer, nullable=False)
    contains_sensitive_keyword = Column(Integer, nullable=False)
    is_https = Column(Integer, nullable=False)
    
    # Feature payload stored as JSON for flexible extensions
    raw_feature_vector = Column(JSON, nullable=True)

    inspection_log = relationship("InspectionLog", back_populates="extracted_features")


# Multi-column indexes for fast dashboard lookups and time-series reporting
Index("idx_inspection_verdict_time", InspectionLog.verdict, InspectionLog.created_at)
Index("idx_inspection_phishing_time", InspectionLog.is_phishing, InspectionLog.created_at)

# Aliases for backward compatibility across existing pipeline components
ScanLog = InspectionLog
import json
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text
from src.database import Base


class ScanLog(Base):
    __tablename__ = "scan_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(
        DateTime(timezone=True), 
        default=lambda: datetime.now(timezone.utc), 
        index=True
    )
    url = Column(String, index=True, nullable=False)
    verdict = Column(String, index=True, nullable=False)  # PHISHING, LEGITIMATE, SUSPICIOUS, ERROR
    ml_probability = Column(Float, nullable=False, default=0.0)
    heuristic_flags_count = Column(Integer, nullable=False, default=0)
    fired_rules_json = Column(Text, nullable=True, default="[]")

    @property
    def fired_rules(self) -> list:
        """Parse JSON string from storage to Python list."""
        if not self.fired_rules_json:
            return []
        try:
            return json.loads(self.fired_rules_json)
        except (json.JSONDecodeError, TypeError):
            return [self.fired_rules_json]

    @fired_rules.setter
    def fired_rules(self, value: list):
        """Serialize Python list to JSON string for storage."""
        if isinstance(value, list):
            self.fired_rules_json = json.dumps(value)
        elif isinstance(value, str):
            self.fired_rules_json = json.dumps([value])
        else:
            self.fired_rules_json = "[]"


class ConfigRule(Base):
    __tablename__ = "config_rules"

    id = Column(Integer, primary_key=True, default=1)
    max_url_length = Column(Integer, default=75, nullable=False)
    max_special_chars = Column(Integer, default=10, nullable=False)
    max_subdomains = Column(Integer, default=3, nullable=False)
    max_entropy = Column(Float, default=4.5, nullable=False)
    block_ip_hostnames = Column(Boolean, default=True, nullable=False)
    flag_sensitive_keywords = Column(Boolean, default=True, nullable=False)
    
    # Audit tracking
    updated_at = Column(
        DateTime(timezone=True), 
        default=lambda: datetime.now(timezone.utc), 
        onupdate=lambda: datetime.now(timezone.utc)
    )
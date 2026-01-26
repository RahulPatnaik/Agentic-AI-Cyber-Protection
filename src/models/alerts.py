"""
Security Alert and Threat Models
All Pydantic BaseModels for type safety and validation
"""

from pydantic import BaseModel, Field, field_validator
from datetime import datetime
from typing import Optional, List
from enum import Enum
from uuid import UUID, uuid4


class SeverityLevel(str, Enum):
    """Threat severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatType(str, Enum):
    """Types of WiFi threats"""
    MITM_ATTACK = "MITM_Attack"
    DEAUTH_ATTACK = "Deauth_Attack"
    EVIL_TWIN = "Evil_Twin"
    DNS_SPOOFING = "DNS_Spoofing"
    ROGUE_AP = "Rogue_AP"
    PACKET_INJECTION = "Packet_Injection"
    DOS_ATTACK = "DoS_Attack"
    UNKNOWN = "Unknown"


class Device(BaseModel):
    """Network device representation"""
    mac: str = Field(..., description="MAC address")
    ip: Optional[str] = Field(None, description="IP address")
    hostname: Optional[str] = Field(None, description="Device hostname")
    vendor: Optional[str] = Field(None, description="Device manufacturer")

    @field_validator('mac')
    @classmethod
    def validate_mac(cls, v: str) -> str:
        """Validate MAC address format"""
        import re
        if not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', v):
            raise ValueError(f"Invalid MAC address: {v}")
        return v.upper()

    model_config = {
        "json_schema_extra": {
            "example": {
                "mac": "00:11:22:33:44:55",
                "ip": "192.168.1.100",
                "hostname": "laptop-001"
            }
        }
    }


class AttackIndicators(BaseModel):
    """Specific indicators detected in the attack"""
    arp_spoofing: bool = False
    duplicate_ip: bool = False
    abnormal_traffic: bool = False
    deauth_frames: bool = False
    dns_anomaly: bool = False
    ssid_mismatch: bool = False
    signal_strength_anomaly: bool = False


class MLPrediction(BaseModel):
    """ML model prediction output"""
    model_name: str = Field(..., description="Model that made prediction")
    prediction: str = Field(..., description="Predicted class/threat type")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Prediction confidence")
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    # Model-specific outputs
    probabilities: Optional[List[float]] = Field(None, description="Class probabilities")
    anomaly_score: Optional[float] = Field(None, description="Anomaly detection score")

    model_config = {
        "json_schema_extra": {
            "example": {
                "model_name": "random_forest",
                "prediction": "malicious",
                "confidence": 0.96,
                "probabilities": [0.04, 0.96]
            }
        }
    }


class SecurityAlert(BaseModel):
    """
    Main Security Alert output from WiFi Guardian Agent.
    Represents a detected threat that may be escalated to Sentinel.
    """
    threat_id: UUID = Field(default_factory=uuid4, description="Unique threat ID")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    severity: SeverityLevel
    threat_type: ThreatType
    confidence: float = Field(..., ge=0.0, le=1.0, description="ML confidence score")

    # Device information
    source_device: Device
    target_device: Optional[Device] = None

    # Attack indicators
    attack_indicators: AttackIndicators

    # ML model outputs
    ml_predictions: List[MLPrediction]
    ensemble_vote: str = Field(..., description="Final ensemble decision")

    # Evidence
    packet_evidence: List[str] = Field(default_factory=list, description="Packet capture IDs")
    pcap_file: Optional[str] = None

    # Guardian recommendations
    recommended_response: str = Field(..., description="Initial response recommendation")

    # Metadata
    detection_latency_ms: Optional[float] = Field(None, description="Time to detect (ms)")
    escalated_to_sentinel: bool = False

    model_config = {
        "json_schema_extra": {
            "example": {
                "threat_id": "550e8400-e29b-41d4-a716-446655440000",
                "timestamp": "2026-01-23T10:30:45Z",
                "severity": "high",
                "threat_type": "MITM_Attack",
                "confidence": 0.97,
                "source_device": {
                    "mac": "00:11:22:33:44:55",
                    "ip": "192.168.1.105"
                },
                "attack_indicators": {
                    "arp_spoofing": True,
                    "duplicate_ip": True
                },
                "ml_predictions": [
                    {
                        "model_name": "random_forest",
                        "prediction": "malicious",
                        "confidence": 0.96
                    }
                ],
                "ensemble_vote": "MITM_Attack",
                "recommended_response": "isolate_device"
            }
        }
    }

"""
Security Response and Action Models
Output from WiFi Sentinel Agent
"""

from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, List, Dict
from enum import Enum
from uuid import UUID, uuid4


class ActionType(str, Enum):
    """Types of response actions"""
    ALERT_ONLY = "alert_only"
    ISOLATE_DEVICE = "isolate_device"
    BLOCK_MAC = "block_mac"
    RESET_CONNECTION = "reset_connection"
    ESCALATE_HUMAN = "escalate_human"
    LOG_ONLY = "log_only"


class ResponseAction(BaseModel):
    """Specific action to execute"""
    action_type: ActionType
    target_device_mac: str
    parameters: Optional[Dict] = Field(default_factory=dict)
    reason: str = Field(..., description="Why this action was chosen")
    requires_approval: bool = False

    model_config = {
        "json_schema_extra": {
            "example": {
                "action_type": "isolate_device",
                "target_device_mac": "00:11:22:33:44:55",
                "reason": "High confidence MITM attack detected",
                "requires_approval": False
            }
        }
    }


class MitreAttack(BaseModel):
    """MITRE ATT&CK mapping"""
    technique_id: str = Field(..., description="MITRE technique ID (e.g., T1557.002)")
    technique_name: str
    tactic: str = Field(..., description="MITRE tactic (e.g., Credential Access)")
    description: str

    model_config = {
        "json_schema_extra": {
            "example": {
                "technique_id": "T1557.002",
                "technique_name": "ARP Cache Poisoning",
                "tactic": "Credential Access",
                "description": "Adversaries may poison ARP caches to position themselves between two hosts."
            }
        }
    }


class FeatureImportance(BaseModel):
    """XAI feature importance scores"""
    feature_name: str
    importance_score: float = Field(..., ge=0.0, le=1.0)
    contribution: str = Field(..., description="Positive or negative contribution")

    model_config = {
        "json_schema_extra": {
            "example": {
                "feature_name": "arp_spoofing",
                "importance_score": 0.45,
                "contribution": "positive"
            }
        }
    }


class SecurityResponse(BaseModel):
    """
    Main Security Response output from WiFi Sentinel Agent.
    Contains LLM analysis, risk assessment, and response actions.
    """
    incident_id: UUID = Field(default_factory=uuid4)
    alert_id: UUID = Field(..., description="Reference to original SecurityAlert")
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    # LLM Analysis
    llm_analysis: str = Field(..., description="Detailed threat analysis from Mistral")
    threat_summary: str = Field(..., description="1-2 sentence summary")

    # Risk Assessment
    risk_score: float = Field(..., ge=0.0, le=10.0, description="Risk score (0-10)")
    severity: str = Field(..., description="Re-assessed severity")

    # MITRE Mapping
    mitre_attack: Optional[MitreAttack] = None

    # Response Decision
    recommended_action: Optional[ResponseAction] = None
    action_taken: Optional[ResponseAction] = None
    action_timestamp: Optional[datetime] = None
    execution_result: Optional[Dict] = None

    # Explainability
    explanation: str = Field(..., description="Human-readable explanation")
    feature_importance: List[FeatureImportance] = Field(default_factory=list)
    decision_path: Optional[str] = None

    # Confidence & Uncertainty
    false_positive_probability: float = Field(..., ge=0.0, le=1.0)
    analyst_review_required: bool = False

    # Metadata
    analysis_latency_ms: Optional[float] = None

    model_config = {
        "json_schema_extra": {
            "example": {
                "incident_id": "660e8400-e29b-41d4-a716-446655440001",
                "alert_id": "550e8400-e29b-41d4-a716-446655440000",
                "llm_analysis": "This is a MITM attack targeting user laptop via ARP spoofing...",
                "threat_summary": "MITM attack via ARP spoofing",
                "risk_score": 9.0,
                "severity": "high",
                "mitre_attack": {
                    "technique_id": "T1557.002",
                    "technique_name": "ARP Cache Poisoning",
                    "tactic": "Credential Access",
                    "description": "ARP spoofing attack"
                },
                "recommended_action": {
                    "action_type": "isolate_device",
                    "target_device_mac": "00:11:22:33:44:55",
                    "reason": "High confidence MITM attack"
                },
                "explanation": "Device isolated due to 97% confidence MITM detection...",
                "false_positive_probability": 0.03
            }
        }
    }

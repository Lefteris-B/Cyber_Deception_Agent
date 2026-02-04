"""
Data models for the Cyber Deception Agent.
Updated for MITRE ATT&CK + Engage framework.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
import uuid


class ThreatLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EngageTactic(Enum):
    PREPARE = "Prepare"
    EXPOSE = "Expose"
    AFFECT = "Affect"
    ELICIT = "Elicit"
    UNDERSTAND = "Understand"


@dataclass
class AlertInput:
    """Input schema for incoming threat alerts based on ATT&CK."""
    attack_id: str  # ATT&CK Technique ID (e.g., T1003, T1566.001)
    probability: float
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    attack_name: Optional[str] = None
    tactic: Optional[str] = None  # ATT&CK Tactic (e.g., "Credential Access")
    affected_assets: list[str] = field(default_factory=list)
    observed_indicators: dict = field(default_factory=dict)
    sub_technique: bool = False

    def __post_init__(self):
        if not 0.0 <= self.probability <= 1.0:
            raise ValueError("Probability must be between 0.0 and 1.0")
        # Normalize ATT&CK ID format
        if not self.attack_id.startswith("T"):
            self.attack_id = f"T{self.attack_id}"
        # Detect sub-technique
        if "." in self.attack_id:
            self.sub_technique = True


@dataclass
class EngageAction:
    """A deception action based on MITRE Engage."""
    action_id: str
    engage_activity_id: str  # EAC ID (e.g., EAC0001)
    engage_activity_name: str
    action_type: str
    priority: str
    parameters: dict
    rationale: str
    tactic: str = "Expose"  # Engage tactic

    @staticmethod
    def from_dict(data: dict) -> "EngageAction":
        return EngageAction(
            action_id=data.get("action_id", str(uuid.uuid4())),
            engage_activity_id=data.get("engage_activity_id", ""),
            engage_activity_name=data.get("engage_activity_name", ""),
            action_type=data.get("action_type", ""),
            priority=data.get("priority", "medium"),
            parameters=data.get("parameters", {}),
            rationale=data.get("rationale", ""),
            tactic=data.get("tactic", "Expose")
        )


@dataclass
class ActionPlan:
    """Output schema for the agent's response."""
    alert_id: str
    attack_id: str
    attack_name: str
    attack_tactic: str
    threat_level: str
    recommended_actions: list[EngageAction]
    deception_objective: str
    confidence: float
    reasoning: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    related_alerts: list[str] = field(default_factory=list)
    engage_activities_used: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "attack_id": self.attack_id,
            "attack_name": self.attack_name,
            "attack_tactic": self.attack_tactic,
            "threat_level": self.threat_level,
            "recommended_actions": [
                {
                    "action_id": a.action_id,
                    "engage_activity_id": a.engage_activity_id,
                    "engage_activity_name": a.engage_activity_name,
                    "action_type": a.action_type,
                    "priority": a.priority,
                    "parameters": a.parameters,
                    "rationale": a.rationale,
                    "tactic": a.tactic
                }
                for a in self.recommended_actions
            ],
            "deception_objective": self.deception_objective,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "timestamp": self.timestamp,
            "related_alerts": self.related_alerts,
            "engage_activities_used": self.engage_activities_used
        }


@dataclass
class Deployment:
    """Tracks an active deception deployment."""
    deployment_id: str
    engage_activity_id: str
    action_type: str
    location: str
    deployed_at: str
    related_alert_id: str
    attack_id: str
    triggered: bool = False
    trigger_count: int = 0
    last_triggered_at: Optional[str] = None


@dataclass
class AlertRecord:
    """Historical record of a processed alert."""
    alert_id: str
    attack_id: str
    attack_name: str
    tactic: str
    timestamp: str
    probability: float
    threat_level: str
    source_indicators: dict
    actions_taken: list[str]
    engage_activities: list[str]


@dataclass
class AttackerProfile:
    """Profile built from observing attacker behavior."""
    profile_id: str
    associated_ips: list[str] = field(default_factory=list)
    observed_techniques: list[str] = field(default_factory=list)  # ATT&CK IDs
    observed_tactics: list[str] = field(default_factory=list)  # ATT&CK Tactics
    first_seen: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    last_seen: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    alert_count: int = 1
    estimated_sophistication: str = "unknown"
    kill_chain_progress: list[str] = field(default_factory=list)

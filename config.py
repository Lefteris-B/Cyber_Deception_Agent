"""
Configuration for the Cyber Deception Agent.
Updated for MITRE ATT&CK + Engage framework.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class ThresholdConfig:
    """Probability thresholds for threat level classification."""
    low_max: float = 0.39
    medium_max: float = 0.69
    high_max: float = 0.89
    # Anything above high_max is CRITICAL


@dataclass
class MemoryConfig:
    """Memory retention settings."""
    alert_retention_hours: int = 168  # 7 days
    deployment_retention_hours: int = 720  # 30 days
    profile_retention_hours: int = 720  # 30 days
    max_alerts_per_profile: int = 100


@dataclass
class AgentConfig:
    """Main agent configuration."""
    engage_data_path: str = "./data/engage_data.json"
    
    # LLM settings
    anthropic_model: str = "claude-sonnet-4-20250514"
    max_tokens: int = 4096
    temperature: float = 0.3
    
    # Decision settings
    min_confidence_threshold: float = 0.5
    max_actions_per_alert: int = 5
    
    # Pattern recognition
    escalation_window_hours: int = 24
    correlation_window_hours: int = 4
    
    # Thresholds
    thresholds: ThresholdConfig = None
    memory: MemoryConfig = None
    
    def __post_init__(self):
        if self.thresholds is None:
            self.thresholds = ThresholdConfig()
        if self.memory is None:
            self.memory = MemoryConfig()


# ATT&CK Tactics in kill chain order
ATTACK_TACTICS_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact"
]


# Map tactics to kill chain phase for escalation detection
TACTIC_PHASES = {
    "Reconnaissance": 1,
    "Resource Development": 1,
    "Initial Access": 2,
    "Execution": 3,
    "Persistence": 3,
    "Privilege Escalation": 4,
    "Defense Evasion": 4,
    "Credential Access": 5,
    "Discovery": 5,
    "Lateral Movement": 6,
    "Collection": 7,
    "Command and Control": 7,
    "Exfiltration": 8,
    "Impact": 9
}


# Engage tactic descriptions
ENGAGE_TACTICS = {
    "Prepare": "Plan and prepare for adversary engagement operations",
    "Expose": "Reveal adversary presence and activity through deceptive surfaces",
    "Affect": "Negatively impact adversary operations through denial and deception",
    "Elicit": "Draw out adversary behavior and capabilities",
    "Understand": "Learn about adversary tactics, techniques, and procedures"
}


# Threat level response strategies with Engage activities
THREAT_LEVEL_STRATEGIES = {
    "low": {
        "description": "Passive observation with silent monitoring",
        "response_intensity": "minimal",
        "primary_engage_tactics": ["Expose", "Understand"],
        "max_deployments": 2
    },
    "medium": {
        "description": "Active deception in likely attack paths",
        "response_intensity": "moderate",
        "primary_engage_tactics": ["Expose", "Affect", "Elicit"],
        "max_deployments": 4
    },
    "high": {
        "description": "Aggressive misdirection with multiple deception layers",
        "response_intensity": "high",
        "primary_engage_tactics": ["Expose", "Affect", "Elicit", "Understand"],
        "max_deployments": 6
    },
    "critical": {
        "description": "Full engagement with maximum deception deployment",
        "response_intensity": "maximum",
        "primary_engage_tactics": ["Prepare", "Expose", "Affect", "Elicit", "Understand"],
        "max_deployments": 10
    }
}


def get_tactic_phase(tactic: str) -> int:
    """Get the kill chain phase number for a tactic."""
    return TACTIC_PHASES.get(tactic, 5)


def is_escalation(previous_tactic: str, current_tactic: str) -> bool:
    """Check if moving from previous to current tactic represents escalation."""
    prev_phase = get_tactic_phase(previous_tactic)
    curr_phase = get_tactic_phase(current_tactic)
    return curr_phase > prev_phase

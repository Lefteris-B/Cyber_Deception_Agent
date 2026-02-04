"""
Cyber Deception Agent - Main Orchestrator

Uses MITRE ATT&CK for threat identification and MITRE Engage for deception response.
"""

import json
from typing import Optional
from datetime import datetime

from schemas import AlertInput, ActionPlan
from config import AgentConfig
from memory import AgentMemory
from engage_loader import EngageDataLoader
from decision_engine import DecisionEngine, RuleBasedDecisionEngine


class CyberDeceptionAgent:
    """
    Main agent class for cyber deception operations.
    
    Uses MITRE ATT&CK techniques as input and MITRE Engage activities as output.
    
    Usage:
        agent = CyberDeceptionAgent()
        agent.initialize()
        
        alert = AlertInput(
            attack_id="T1003",
            probability=0.85,
            affected_assets=["endpoint-01"]
        )
        action_plan = agent.process_alert(alert)
    """
    
    def __init__(
        self,
        config: Optional[AgentConfig] = None,
        use_llm: bool = True
    ):
        self.config = config or AgentConfig()
        self.use_llm = use_llm
        
        # Components
        self.memory: Optional[AgentMemory] = None
        self.engage_loader: Optional[EngageDataLoader] = None
        self.decision_engine = None
        
        self._initialized = False
    
    def initialize(self) -> bool:
        """Initialize all agent components."""
        print("Initializing Cyber Deception Agent (ATT&CK + Engage)...")
        
        # Initialize memory
        self.memory = AgentMemory(self.config.memory)
        print("  ✓ Memory initialized")
        
        # Load Engage data
        self.engage_loader = EngageDataLoader(self.config.engage_data_path)
        if not self.engage_loader.load():
            print("  ✗ Failed to load Engage data")
            return False
        print(f"  ✓ Engage framework loaded")
        
        # Initialize decision engine
        if self.use_llm:
            self.decision_engine = DecisionEngine(
                self.config, self.memory, self.engage_loader
            )
            print("  ✓ LLM Decision Engine initialized")
        else:
            self.decision_engine = RuleBasedDecisionEngine(
                self.config, self.memory, self.engage_loader
            )
            print("  ✓ Rule-based Decision Engine initialized")
        
        self._initialized = True
        print("Agent initialization complete.\n")
        return True
    
    def process_alert(self, alert: AlertInput) -> ActionPlan:
        """Process an incoming threat alert and generate an action plan."""
        if not self._initialized:
            raise RuntimeError("Agent not initialized. Call initialize() first.")
        
        print(f"\n{'='*60}")
        print(f"Processing Alert: {alert.alert_id}")
        print(f"  ATT&CK Technique: {alert.attack_id}")
        print(f"  Probability: {alert.probability}")
        print(f"  Assets: {alert.affected_assets}")
        print(f"{'='*60}")
        
        # Get ATT&CK mapping info
        mapping = self.engage_loader.get_attack_mapping(alert.attack_id)
        if mapping:
            print(f"  ✓ ATT&CK Mapping: {mapping.attack_name} ({mapping.tactic})")
            print(f"  → Engage activities available: {len(mapping.engage_activities)}")
        else:
            print(f"  ⚠ No direct mapping for {alert.attack_id}")
        
        # Make decision
        print("  → Running decision engine...")
        action_plan = self.decision_engine.decide(alert)
        
        print(f"  ✓ Decision complete: {len(action_plan.recommended_actions)} actions")
        print(f"  → Threat Level: {action_plan.threat_level.upper()}")
        print(f"  → Confidence: {action_plan.confidence:.2f}")
        
        # Update memory
        self._update_memory(alert, action_plan)
        
        return action_plan
    
    def _update_memory(self, alert: AlertInput, action_plan: ActionPlan):
        """Update memory with the processed alert and actions."""
        
        action_ids = [a.action_id for a in action_plan.recommended_actions]
        engage_activities = [a.engage_activity_id for a in action_plan.recommended_actions]
        
        self.memory.store_alert(
            alert=alert,
            threat_level=action_plan.threat_level,
            actions_taken=action_ids,
            engage_activities=engage_activities
        )
        
        # Store deployments
        for action in action_plan.recommended_actions:
            location = action.parameters.get(
                "placement",
                action.parameters.get("target_systems", ["unknown"])[0] if isinstance(
                    action.parameters.get("target_systems"), list
                ) else action.parameters.get("target_systems", "unknown")
            )
            if isinstance(location, list):
                location = location[0] if location else "unknown"
            
            self.memory.store_deployment(
                engage_activity_id=action.engage_activity_id,
                action_type=action.action_type,
                location=location,
                alert_id=alert.alert_id,
                attack_id=alert.attack_id
            )
        
        print(f"  ✓ Memory updated")
    
    def get_status(self) -> dict:
        """Get current agent status and statistics."""
        status = {
            "initialized": self._initialized,
            "use_llm": self.use_llm,
            "framework": "MITRE ATT&CK + Engage",
            "config": {
                "engage_data_path": self.config.engage_data_path,
                "model": self.config.anthropic_model if self.use_llm else "N/A"
            }
        }
        
        if self._initialized:
            status["memory"] = self.memory.get_memory_summary()
            status["engage"] = self.engage_loader.get_summary()
        
        return status
    
    def report_deployment_triggered(self, deployment_id: str) -> bool:
        """Report that a deception deployment was triggered."""
        if not self._initialized:
            return False
        
        deployment = self.memory.mark_deployment_triggered(deployment_id)
        if deployment:
            print(f"Deployment {deployment_id} marked as triggered")
            return True
        return False
    
    def cleanup_memory(self):
        """Run memory cleanup to remove old records."""
        if self._initialized:
            self.memory.cleanup_old_records()
            print("Memory cleanup complete")


def format_action_plan(plan: ActionPlan) -> str:
    """Format an action plan for display."""
    output = []
    output.append(f"\n{'='*60}")
    output.append(f"ACTION PLAN - {plan.alert_id}")
    output.append(f"{'='*60}")
    output.append(f"ATT&CK Technique: {plan.attack_id} - {plan.attack_name}")
    output.append(f"ATT&CK Tactic: {plan.attack_tactic}")
    output.append(f"Threat Level: {plan.threat_level.upper()}")
    output.append(f"Confidence: {plan.confidence:.2f}")
    output.append(f"Objective: {plan.deception_objective}")
    output.append(f"\nReasoning: {plan.reasoning}")
    
    if plan.related_alerts:
        output.append(f"\nRelated Alerts: {', '.join(plan.related_alerts)}")
    
    output.append(f"\n{'─'*60}")
    output.append("RECOMMENDED ENGAGE ACTIONS:")
    output.append(f"{'─'*60}")
    
    for i, action in enumerate(plan.recommended_actions, 1):
        output.append(f"\n[{i}] {action.engage_activity_name} ({action.engage_activity_id})")
        output.append(f"    Engage Tactic: {action.tactic}")
        output.append(f"    Action Type: {action.action_type}")
        output.append(f"    Priority: {action.priority}")
        output.append(f"    Rationale: {action.rationale}")
        output.append(f"    Parameters:")
        for key, value in action.parameters.items():
            output.append(f"      - {key}: {value}")
    
    output.append(f"\n{'='*60}\n")
    return "\n".join(output)


def export_action_plan_json(plan: ActionPlan, filepath: str):
    """Export action plan to JSON file."""
    with open(filepath, 'w') as f:
        json.dump(plan.to_dict(), f, indent=2)
    print(f"Action plan exported to {filepath}")

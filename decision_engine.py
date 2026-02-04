"""
Decision engine for the Cyber Deception Agent.
Integrates LLM reasoning with MITRE ATT&CK and Engage frameworks.
"""

import json
import uuid
from typing import Optional
from anthropic import Anthropic

from schemas import AlertInput, EngageAction, ActionPlan, AlertRecord
from config import AgentConfig, THREAT_LEVEL_STRATEGIES, get_tactic_phase
from memory import AgentMemory
from engage_loader import EngageDataLoader, EngageActivity, AttackMapping


class ThreatClassifier:
    """Classifies threat level based on probability thresholds."""
    
    def __init__(self, config: AgentConfig):
        self.config = config
    
    def classify(self, probability: float) -> str:
        """Classify probability into threat level."""
        thresholds = self.config.thresholds
        
        if probability <= thresholds.low_max:
            return "low"
        elif probability <= thresholds.medium_max:
            return "medium"
        elif probability <= thresholds.high_max:
            return "high"
        else:
            return "critical"


class DecisionEngine:
    """Core decision-making engine using LLM reasoning with ATT&CK + Engage."""
    
    def __init__(
        self,
        config: AgentConfig,
        memory: AgentMemory,
        engage_loader: EngageDataLoader
    ):
        self.config = config
        self.memory = memory
        self.engage_loader = engage_loader
        self.classifier = ThreatClassifier(config)
        self.client = Anthropic()
    
    def decide(self, alert: AlertInput) -> ActionPlan:
        """Main decision method. Analyzes alert and returns an action plan."""
        
        # Step 1: Classify threat level
        threat_level = self.classifier.classify(alert.probability)
        
        # Step 2: Get ATT&CK mapping and Engage activities
        mapping = self.engage_loader.get_attack_mapping(alert.attack_id)
        if mapping:
            alert.attack_name = mapping.attack_name
            alert.tactic = mapping.tactic
        
        activities = self.engage_loader.get_activities_for_technique(alert.attack_id)
        activities = self.engage_loader.filter_activities_by_threat_level(activities, threat_level)
        
        if not activities:
            return self._create_empty_plan(alert, threat_level, "No Engage activities available for this technique")
        
        # Step 3: Get context from memory
        context = self._build_context(alert, threat_level)
        
        # Step 4: Use LLM to select and adapt actions
        selected_actions, reasoning, objective, confidence = self._llm_decide(
            alert=alert,
            threat_level=threat_level,
            context=context,
            activities=activities,
            mapping=mapping
        )
        
        # Step 5: Build action plan
        action_plan = ActionPlan(
            alert_id=alert.alert_id,
            attack_id=alert.attack_id,
            attack_name=alert.attack_name or "Unknown",
            attack_tactic=alert.tactic or "Unknown",
            threat_level=threat_level,
            recommended_actions=selected_actions,
            deception_objective=objective,
            confidence=confidence,
            reasoning=reasoning,
            related_alerts=[r.alert_id for r in context.get("related_alerts", [])],
            engage_activities_used=[a.engage_activity_id for a in selected_actions]
        )
        
        return action_plan
    
    def _build_context(self, alert: AlertInput, threat_level: str) -> dict:
        """Build context from memory for decision making."""
        context = {
            "threat_level": threat_level,
            "strategy": THREAT_LEVEL_STRATEGIES.get(threat_level, {}),
            "related_alerts": [],
            "existing_deployments": [],
            "attacker_profile": None,
            "escalation_detected": None
        }
        
        # Get related alerts
        context["related_alerts"] = self.memory.get_related_alerts(
            alert,
            window_hours=self.config.correlation_window_hours
        )
        
        # Get existing deployments for affected assets
        for asset in alert.affected_assets:
            deployments = self.memory.get_deployments_at_location(asset)
            context["existing_deployments"].extend(deployments)
        
        # Also check deployments for this technique
        tech_deployments = self.memory.get_deployments_for_technique(alert.attack_id)
        for dep in tech_deployments:
            if dep not in context["existing_deployments"]:
                context["existing_deployments"].append(dep)
        
        # Get attacker profile if source IP known
        source_ip = alert.observed_indicators.get("source_ip")
        if source_ip:
            context["attacker_profile"] = self.memory.get_attacker_profile_by_ip(source_ip)
            context["escalation_detected"] = self.memory.detect_attack_escalation(
                source_ip,
                window_hours=self.config.escalation_window_hours
            )
        
        return context
    
    def _llm_decide(
        self,
        alert: AlertInput,
        threat_level: str,
        context: dict,
        activities: list[EngageActivity],
        mapping: Optional[AttackMapping]
    ) -> tuple[list[EngageAction], str, str, float]:
        """Use LLM to select and adapt actions."""
        
        prompt = self._build_prompt(
            alert=alert,
            threat_level=threat_level,
            context=context,
            activities=activities,
            mapping=mapping
        )
        
        response = self.client.messages.create(
            model=self.config.anthropic_model,
            max_tokens=self.config.max_tokens,
            temperature=self.config.temperature,
            messages=[{"role": "user", "content": prompt}]
        )
        
        return self._parse_llm_response(response.content[0].text, activities)
    
    def _build_prompt(
        self,
        alert: AlertInput,
        threat_level: str,
        context: dict,
        activities: list[EngageActivity],
        mapping: Optional[AttackMapping]
    ) -> str:
        """Build the prompt for LLM decision making."""
        
        # Format existing deployments
        existing_deployments_str = "None"
        if context["existing_deployments"]:
            deps = []
            for dep in context["existing_deployments"]:
                deps.append(f"  - {dep.action_type} ({dep.engage_activity_id}) at {dep.location} (triggered: {dep.triggered})")
            existing_deployments_str = "\n".join(deps)
        
        # Format related alerts
        related_alerts_str = "None"
        if context["related_alerts"]:
            alerts = []
            for ra in context["related_alerts"]:
                alerts.append(f"  - {ra.attack_id} ({ra.attack_name}) - {ra.tactic} at {ra.timestamp}")
            related_alerts_str = "\n".join(alerts)
        
        # Format attacker profile
        attacker_profile_str = "Unknown attacker"
        if context["attacker_profile"]:
            ap = context["attacker_profile"]
            attacker_profile_str = f"""
  - Profile ID: {ap.profile_id}
  - Observed techniques: {', '.join(ap.observed_techniques)}
  - Observed tactics: {', '.join(ap.observed_tactics)}
  - Kill chain progress: {' → '.join(ap.kill_chain_progress)}
  - Sophistication estimate: {ap.estimated_sophistication}
"""
        
        # Format escalation info
        escalation_str = "No escalation detected"
        if context["escalation_detected"]:
            esc = context["escalation_detected"]
            escalation_str = f"""
  ESCALATION DETECTED:
  - Kill chain progress: {' → '.join(esc.get('kill_chain_progress', []))}
  - Techniques used: {esc['technique_count']}
  - Sophistication: {esc['sophistication']}
  - Is actively escalating: {esc.get('is_escalating', False)}
"""
        
        # Format available Engage activities
        activities_str = ""
        for activity in activities:
            activities_str += f"""
  {activity.id} - {activity.name}
    Tactic: {activity.tactic}
    Description: {activity.description}
    Action Type: {activity.action_type}
    Parameters: {', '.join(activity.parameters)}
"""
        
        max_actions = self.engage_loader.get_max_actions_for_threat_level(threat_level)
        
        prompt = f"""You are a cyber deception agent using the MITRE Engage framework to respond to threats detected via MITRE ATT&CK.

## CURRENT ALERT
- Alert ID: {alert.alert_id}
- ATT&CK Technique: {alert.attack_id} - {alert.attack_name or 'Unknown'}
- ATT&CK Tactic: {alert.tactic or 'Unknown'}
- Probability: {alert.probability}
- Threat Level: {threat_level.upper()}
- Affected Assets: {', '.join(alert.affected_assets) if alert.affected_assets else 'Unknown'}
- Observed Indicators: {json.dumps(alert.observed_indicators)}

## CONTEXT FROM MEMORY

### Existing Deployments (avoid redundancy):
{existing_deployments_str}

### Related Recent Alerts:
{related_alerts_str}

### Attacker Profile:
{attacker_profile_str}

### Attack Progression:
{escalation_str}

## THREAT LEVEL STRATEGY
- Level: {threat_level.upper()}
- Strategy: {context['strategy'].get('description', 'N/A')}
- Max actions: {max_actions}
- Primary Engage tactics: {context['strategy'].get('primary_engage_tactics', [])}

## AVAILABLE ENGAGE ACTIVITIES
{activities_str}

## YOUR TASK
1. Select 1-{max_actions} Engage activities appropriate for this threat
2. Adapt parameters based on:
   - Affected assets (replace placeholders with actual values)
   - Source IP if known: {alert.observed_indicators.get('source_ip', 'unknown')}
   - Attacker sophistication level
   - Attack escalation patterns
3. Avoid redundancy with existing deployments
4. Prioritize based on threat level and attack tactic

## RESPONSE FORMAT
Respond with valid JSON only:
{{
  "selected_actions": [
    {{
      "engage_activity_id": "EAC ID",
      "engage_activity_name": "Activity name",
      "action_type": "action type from activity",
      "priority": "low|medium|high|critical",
      "tactic": "Engage tactic",
      "parameters": {{}},
      "rationale": "why this action for this attack"
    }}
  ],
  "deception_objective": "primary goal of these actions",
  "overall_reasoning": "explanation of decision",
  "confidence": 0.0-1.0
}}
"""
        return prompt
    
    def _parse_llm_response(
        self,
        response_text: str,
        activities: list[EngageActivity]
    ) -> tuple[list[EngageAction], str, str, float]:
        """Parse LLM response into structured output."""
        
        try:
            # Clean response
            cleaned = response_text.strip()
            if cleaned.startswith("```"):
                cleaned = cleaned.split("\n", 1)[1]
            if cleaned.endswith("```"):
                cleaned = cleaned.rsplit("```", 1)[0]
            cleaned = cleaned.strip()
            
            data = json.loads(cleaned)
            
            # Convert to EngageAction objects
            actions = []
            for action_data in data.get("selected_actions", []):
                action = EngageAction(
                    action_id=str(uuid.uuid4()),
                    engage_activity_id=action_data.get("engage_activity_id", ""),
                    engage_activity_name=action_data.get("engage_activity_name", ""),
                    action_type=action_data.get("action_type", ""),
                    priority=action_data.get("priority", "medium"),
                    parameters=action_data.get("parameters", {}),
                    rationale=action_data.get("rationale", ""),
                    tactic=action_data.get("tactic", "Expose")
                )
                actions.append(action)
            
            reasoning = data.get("overall_reasoning", "No reasoning provided")
            objective = data.get("deception_objective", "Detect and misdirect attacker")
            confidence = float(data.get("confidence", 0.7))
            
            return actions, reasoning, objective, confidence
            
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            print(f"Warning: Failed to parse LLM response: {e}")
            
            # Fallback: use first available activity
            if activities:
                activity = activities[0]
                fallback_action = EngageAction(
                    action_id=str(uuid.uuid4()),
                    engage_activity_id=activity.id,
                    engage_activity_name=activity.name,
                    action_type=activity.action_type,
                    priority="medium",
                    parameters=activity.get_default_parameters(),
                    rationale=f"Fallback: {activity.description}",
                    tactic=activity.tactic
                )
                return (
                    [fallback_action],
                    f"Fallback due to parse error: {str(e)}",
                    "Basic detection",
                    0.5
                )
            return [], "No actions available", "None", 0.0
    
    def _create_empty_plan(
        self,
        alert: AlertInput,
        threat_level: str,
        reason: str
    ) -> ActionPlan:
        """Create an empty action plan when no actions can be taken."""
        return ActionPlan(
            alert_id=alert.alert_id,
            attack_id=alert.attack_id,
            attack_name=alert.attack_name or "Unknown",
            attack_tactic=alert.tactic or "Unknown",
            threat_level=threat_level,
            recommended_actions=[],
            deception_objective="None",
            confidence=0.0,
            reasoning=reason,
            engage_activities_used=[]
        )


class RuleBasedDecisionEngine:
    """Rule-based decision engine for testing without LLM."""
    
    def __init__(
        self,
        config: AgentConfig,
        memory: AgentMemory,
        engage_loader: EngageDataLoader
    ):
        self.config = config
        self.memory = memory
        self.engage_loader = engage_loader
        self.classifier = ThreatClassifier(config)
    
    def decide(self, alert: AlertInput) -> ActionPlan:
        """Rule-based decision without LLM."""
        
        threat_level = self.classifier.classify(alert.probability)
        
        # Get mapping and update alert
        mapping = self.engage_loader.get_attack_mapping(alert.attack_id)
        if mapping:
            alert.attack_name = mapping.attack_name
            alert.tactic = mapping.tactic
        
        # Get and filter activities
        activities = self.engage_loader.get_activities_for_technique(alert.attack_id)
        activities = self.engage_loader.filter_activities_by_threat_level(activities, threat_level)
        
        # Limit to max actions
        max_actions = self.engage_loader.get_max_actions_for_threat_level(threat_level)
        selected_activities = activities[:max_actions]
        
        # Convert to actions
        actions = []
        for activity in selected_activities:
            params = {}
            for param in activity.parameters:
                if param == "placement" and alert.affected_assets:
                    params[param] = alert.affected_assets[0]
                elif param == "target_systems" and alert.affected_assets:
                    params[param] = alert.affected_assets
                elif param == "network_segment":
                    params[param] = alert.observed_indicators.get("source_network", "default-segment")
                else:
                    params[param] = f"{{{{auto_{param}}}}}"
            
            action = EngageAction(
                action_id=str(uuid.uuid4()),
                engage_activity_id=activity.id,
                engage_activity_name=activity.name,
                action_type=activity.action_type,
                priority="high" if threat_level in ["high", "critical"] else "medium",
                parameters=params,
                rationale=activity.description,
                tactic=activity.tactic
            )
            actions.append(action)
        
        return ActionPlan(
            alert_id=alert.alert_id,
            attack_id=alert.attack_id,
            attack_name=alert.attack_name or "Unknown",
            attack_tactic=alert.tactic or "Unknown",
            threat_level=threat_level,
            recommended_actions=actions,
            deception_objective=f"Counter {alert.tactic or 'attack'} using {len(actions)} Engage activities",
            confidence=0.7,
            reasoning=f"Rule-based: Selected {len(actions)} activities for {threat_level} threat",
            engage_activities_used=[a.engage_activity_id for a in actions]
        )

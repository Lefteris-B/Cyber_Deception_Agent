"""
MITRE Engage Framework Data Loader

Loads official MITRE Engage data including:
- Goals (Expose, Affect, Elicit, Prepare, Understand)
- Approaches (Collect, Detect, Prevent, Direct, Disrupt, Reassure, Motivate)
- Activities (EAC0001-EAC0023 Engagement + SAC Strategic)
- ATT&CK Technique Mappings (175+ techniques)
"""

import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from pathlib import Path


@dataclass
class EngageActivity:
    """Represents a MITRE Engage Activity."""
    id: str
    name: str
    description: str
    long_description: str = ""
    activity_type: str = "Engagement"  # Engagement or Strategic
    goals: List[str] = field(default_factory=list)
    approaches: List[str] = field(default_factory=list)
    attack_tactics: List[str] = field(default_factory=list)


@dataclass
class EngageApproach:
    """Represents a MITRE Engage Approach."""
    id: str
    name: str
    description: str
    approach_type: str = "Engagement"
    activities: List[str] = field(default_factory=list)


@dataclass
class EngageGoal:
    """Represents a MITRE Engage Goal."""
    id: str
    name: str
    description: str
    goal_type: str = "Engagement"
    approaches: List[str] = field(default_factory=list)


@dataclass
class AttackMapping:
    """Represents mapping from ATT&CK technique to Engage activities."""
    attack_id: str
    technique_name: str
    tactics: List[str] = field(default_factory=list)
    engage_activities: List[str] = field(default_factory=list)


@dataclass
class ThreatLevelConfig:
    """Configuration for a threat level."""
    threshold: float
    max_actions: int
    action_types: List[str]
    description: str


class EngageLoader:
    """Loads and provides access to MITRE Engage framework data."""
    
    def __init__(self, data_path: str):
        self.data_path = data_path
        self.goals: Dict[str, EngageGoal] = {}
        self.approaches: Dict[str, EngageApproach] = {}
        self.activities: Dict[str, EngageActivity] = {}
        self.attack_mappings: Dict[str, AttackMapping] = {}
        self.threat_levels: Dict[str, ThreatLevelConfig] = {}
        self._loaded = False
        
    def load(self) -> bool:
        """Load the Engage data from JSON file."""
        if not os.path.exists(self.data_path):
            print(f"Warning: Engage data file not found: {self.data_path}")
            return False
            
        try:
            with open(self.data_path, 'r') as f:
                data = json.load(f)
            
            # Load goals
            for goal_id, goal_data in data.get("goals", {}).items():
                self.goals[goal_id] = EngageGoal(
                    id=goal_id,
                    name=goal_data["name"],
                    description=goal_data["description"],
                    goal_type=goal_data.get("type", "Engagement"),
                    approaches=goal_data.get("approaches", [])
                )
            
            # Load approaches
            for app_id, app_data in data.get("approaches", {}).items():
                self.approaches[app_id] = EngageApproach(
                    id=app_id,
                    name=app_data["name"],
                    description=app_data["description"],
                    approach_type=app_data.get("type", "Engagement"),
                    activities=app_data.get("activities", [])
                )
            
            # Load activities
            for act_id, act_data in data.get("activities", {}).items():
                self.activities[act_id] = EngageActivity(
                    id=act_id,
                    name=act_data["name"],
                    description=act_data["description"],
                    long_description=act_data.get("long_description", ""),
                    activity_type=act_data.get("type", "Engagement"),
                    goals=act_data.get("goals", []),
                    approaches=act_data.get("approaches", []),
                    attack_tactics=act_data.get("attack_tactics", [])
                )
            
            # Load ATT&CK mappings
            for attack_id, mapping_data in data.get("attack_mappings", {}).items():
                self.attack_mappings[attack_id] = AttackMapping(
                    attack_id=attack_id,
                    technique_name=mapping_data["technique_name"],
                    tactics=mapping_data.get("tactics", []),
                    engage_activities=mapping_data.get("engage_activities", [])
                )
            
            # Load threat levels
            for level_name, level_data in data.get("threat_levels", {}).items():
                self.threat_levels[level_name] = ThreatLevelConfig(
                    threshold=level_data["threshold"],
                    max_actions=level_data["max_actions"],
                    action_types=level_data["action_types"],
                    description=level_data["description"]
                )
            
            self._loaded = True
            print(f"Loaded {len(self.activities)} Engage activities")
            print(f"Loaded {len(self.attack_mappings)} ATT&CK technique mappings")
            return True
            
        except Exception as e:
            print(f"Error loading Engage data: {e}")
            return False
    
    def is_loaded(self) -> bool:
        """Check if data is loaded."""
        return self._loaded
    
    def get_activities_for_technique(self, attack_id: str) -> List[EngageActivity]:
        """Get Engage activities mapped to an ATT&CK technique."""
        if attack_id not in self.attack_mappings:
            return []
        
        mapping = self.attack_mappings[attack_id]
        activities = []
        for act_id in mapping.engage_activities:
            if act_id in self.activities:
                activities.append(self.activities[act_id])
        return activities
    
    def get_technique_info(self, attack_id: str) -> Optional[AttackMapping]:
        """Get technique mapping info."""
        return self.attack_mappings.get(attack_id)
    
    def get_threat_level(self, probability: float) -> str:
        """Determine threat level from probability."""
        if probability >= self.threat_levels.get("critical", ThreatLevelConfig(0.9, 10, [], "")).threshold:
            return "critical"
        elif probability >= self.threat_levels.get("high", ThreatLevelConfig(0.7, 6, [], "")).threshold:
            return "high"
        elif probability >= self.threat_levels.get("medium", ThreatLevelConfig(0.5, 4, [], "")).threshold:
            return "medium"
        else:
            return "low"
    
    def get_threat_config(self, level: str) -> Optional[ThreatLevelConfig]:
        """Get configuration for a threat level."""
        return self.threat_levels.get(level)
    
    def filter_activities_by_threat_level(
        self, 
        activities: List[EngageActivity], 
        threat_level: str
    ) -> List[EngageActivity]:
        """Filter and limit activities based on threat level."""
        config = self.get_threat_config(threat_level)
        if not config:
            return activities[:2]  # Default conservative limit
        
        # For now, just limit by max_actions
        # Could add more sophisticated filtering based on action_types
        return activities[:config.max_actions]
    
    def get_activities_by_goal(self, goal_name: str) -> List[EngageActivity]:
        """Get all activities that serve a particular goal."""
        return [
            act for act in self.activities.values()
            if goal_name in act.goals
        ]
    
    def get_activities_by_approach(self, approach_id: str) -> List[EngageActivity]:
        """Get all activities for a particular approach."""
        if approach_id not in self.approaches:
            return []
        return [
            self.activities[act_id]
            for act_id in self.approaches[approach_id].activities
            if act_id in self.activities
        ]
    
    def get_engagement_activities(self) -> List[EngageActivity]:
        """Get only engagement (tactical) activities, not strategic."""
        return [
            act for act in self.activities.values()
            if act.activity_type == "Engagement"
        ]
    
    def get_strategic_activities(self) -> List[EngageActivity]:
        """Get only strategic activities."""
        return [
            act for act in self.activities.values()
            if act.activity_type == "Strategic"
        ]
    
    def list_all_techniques(self) -> List[Dict[str, Any]]:
        """List all mapped ATT&CK techniques."""
        return [
            {
                "attack_id": mapping.attack_id,
                "name": mapping.technique_name,
                "tactics": mapping.tactics,
                "engage_activities": mapping.engage_activities
            }
            for mapping in sorted(
                self.attack_mappings.values(), 
                key=lambda x: x.attack_id
            )
        ]
    
    def get_status(self) -> Dict[str, Any]:
        """Get loader status for diagnostics."""
        if not self._loaded:
            return {"loaded": False}
        
        # Count engagement vs strategic activities
        engagement_count = len([a for a in self.activities.values() if a.activity_type == "Engagement"])
        strategic_count = len([a for a in self.activities.values() if a.activity_type == "Strategic"])
        
        # Get unique tactics covered
        all_tactics = set()
        for mapping in self.attack_mappings.values():
            all_tactics.update(mapping.tactics)
        
        return {
            "loaded": True,
            "total_activities": len(self.activities),
            "engagement_activities": engagement_count,
            "strategic_activities": strategic_count,
            "total_attack_mappings": len(self.attack_mappings),
            "total_goals": len(self.goals),
            "total_approaches": len(self.approaches),
            "tactics_covered": sorted(list(all_tactics)),
            "activity_ids": sorted([a.id for a in self.activities.values() if a.id.startswith("EAC")]),
            "threat_levels_configured": list(self.threat_levels.keys())
        }

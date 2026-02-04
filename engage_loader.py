"""
Engage Framework data loader for the Cyber Deception Agent.
Loads MITRE Engage activities and ATT&CK mappings.
"""

import json
import os
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field


@dataclass
class EngageActivity:
    """Represents a MITRE Engage activity."""
    id: str
    name: str
    tactic: str
    description: str
    action_type: str
    parameters: list[str] = field(default_factory=list)
    
    def get_default_parameters(self) -> dict:
        """Get default parameter structure for this activity."""
        return {param: f"{{{{placeholder_{param}}}}}" for param in self.parameters}


@dataclass 
class AttackMapping:
    """Maps an ATT&CK technique to Engage activities."""
    attack_id: str
    attack_name: str
    tactic: str
    engage_activities: list[str]  # List of EAC IDs


class EngageDataLoader:
    """Loads and manages MITRE Engage framework data."""
    
    def __init__(self, data_path: str = "./data/engage_data.json"):
        self.data_path = Path(data_path)
        self._activities: dict[str, EngageActivity] = {}
        self._attack_mappings: dict[str, AttackMapping] = {}
        self._threat_level_configs: dict[str, dict] = {}
        self._loaded = False
    
    def load(self) -> bool:
        """Load Engage data from JSON file."""
        if not self.data_path.exists():
            print(f"Warning: Engage data file not found: {self.data_path}")
            return False
        
        try:
            with open(self.data_path, 'r') as f:
                data = json.load(f)
            
            # Load activities
            for eac_id, activity_data in data.get("engage_activities", {}).items():
                impl = activity_data.get("implementation", {})
                activity = EngageActivity(
                    id=activity_data.get("id", eac_id),
                    name=activity_data.get("name", "Unknown"),
                    tactic=activity_data.get("tactic", "Expose"),
                    description=activity_data.get("description", ""),
                    action_type=impl.get("action_type", "unknown"),
                    parameters=impl.get("parameters", [])
                )
                self._activities[eac_id] = activity
            
            # Load ATT&CK mappings
            for mapping_data in data.get("attack_mappings", []):
                attack_id = mapping_data.get("attack_id")
                mapping = AttackMapping(
                    attack_id=attack_id,
                    attack_name=mapping_data.get("attack_name", "Unknown"),
                    tactic=mapping_data.get("tactic", "Unknown"),
                    engage_activities=mapping_data.get("engage_activities", [])
                )
                self._attack_mappings[attack_id] = mapping
            
            # Load threat level configurations
            self._threat_level_configs = data.get("threat_level_configurations", {})
            
            self._loaded = True
            print(f"Loaded {len(self._activities)} Engage activities")
            print(f"Loaded {len(self._attack_mappings)} ATT&CK technique mappings")
            return True
            
        except Exception as e:
            print(f"Error loading Engage data: {e}")
            return False
    
    def get_activity(self, eac_id: str) -> Optional[EngageActivity]:
        """Get an Engage activity by ID."""
        return self._activities.get(eac_id)
    
    def get_activities_for_technique(self, attack_id: str) -> list[EngageActivity]:
        """Get all Engage activities mapped to an ATT&CK technique."""
        mapping = self._attack_mappings.get(attack_id)
        if not mapping:
            # Try parent technique if this is a sub-technique
            if "." in attack_id:
                parent_id = attack_id.split(".")[0]
                mapping = self._attack_mappings.get(parent_id)
        
        if not mapping:
            return []
        
        activities = []
        for eac_id in mapping.engage_activities:
            activity = self._activities.get(eac_id)
            if activity:
                activities.append(activity)
        
        return activities
    
    def get_attack_mapping(self, attack_id: str) -> Optional[AttackMapping]:
        """Get the ATT&CK mapping for a technique."""
        mapping = self._attack_mappings.get(attack_id)
        if not mapping and "." in attack_id:
            # Fall back to parent technique
            parent_id = attack_id.split(".")[0]
            mapping = self._attack_mappings.get(parent_id)
        return mapping
    
    def get_allowed_activities_for_threat_level(self, threat_level: str) -> list[str]:
        """Get list of allowed EAC IDs for a threat level."""
        config = self._threat_level_configs.get(threat_level.lower(), {})
        return config.get("allowed_activities", list(self._activities.keys()))
    
    def get_max_actions_for_threat_level(self, threat_level: str) -> int:
        """Get maximum actions allowed for a threat level."""
        config = self._threat_level_configs.get(threat_level.lower(), {})
        return config.get("max_actions", 5)
    
    def filter_activities_by_threat_level(
        self,
        activities: list[EngageActivity],
        threat_level: str
    ) -> list[EngageActivity]:
        """Filter activities to only those allowed at given threat level."""
        allowed_ids = self.get_allowed_activities_for_threat_level(threat_level)
        return [a for a in activities if a.id in allowed_ids]
    
    def get_all_activities(self) -> list[EngageActivity]:
        """Get all loaded Engage activities."""
        return list(self._activities.values())
    
    def get_all_attack_ids(self) -> list[str]:
        """Get all ATT&CK technique IDs with mappings."""
        return list(self._attack_mappings.keys())
    
    def get_summary(self) -> dict:
        """Get summary of loaded data."""
        tactics_covered = set()
        for mapping in self._attack_mappings.values():
            tactics_covered.add(mapping.tactic)
        
        return {
            "loaded": self._loaded,
            "total_activities": len(self._activities),
            "total_attack_mappings": len(self._attack_mappings),
            "tactics_covered": list(tactics_covered),
            "activity_ids": list(self._activities.keys()),
            "threat_levels_configured": list(self._threat_level_configs.keys())
        }
    
    def get_activities_by_tactic(self, engage_tactic: str) -> list[EngageActivity]:
        """Get all activities for a specific Engage tactic."""
        return [a for a in self._activities.values() if a.tactic == engage_tactic]

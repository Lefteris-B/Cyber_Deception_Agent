"""
Memory management for the Cyber Deception Agent.
Handles storage and retrieval of alerts, deployments, and attacker profiles.
Updated for MITRE ATT&CK + Engage.
"""

from datetime import datetime, timedelta
from typing import Optional
import uuid

from schemas import AlertRecord, Deployment, AttackerProfile, AlertInput
from config import MemoryConfig, get_tactic_phase, TACTIC_PHASES


class AgentMemory:
    """In-memory storage for agent state."""
    
    def __init__(self, config: Optional[MemoryConfig] = None):
        self.config = config or MemoryConfig()
        
        # Storage
        self._alerts: dict[str, AlertRecord] = {}
        self._deployments: dict[str, Deployment] = {}
        self._attacker_profiles: dict[str, AttackerProfile] = {}
        
        # Indexes for fast lookup
        self._alerts_by_technique: dict[str, list[str]] = {}
        self._alerts_by_tactic: dict[str, list[str]] = {}
        self._alerts_by_ip: dict[str, list[str]] = {}
        self._deployments_by_location: dict[str, list[str]] = {}
        self._deployments_by_technique: dict[str, list[str]] = {}
        self._profiles_by_ip: dict[str, str] = {}
    
    # ==================== Alert Operations ====================
    
    def store_alert(
        self,
        alert: AlertInput,
        threat_level: str,
        actions_taken: list[str],
        engage_activities: list[str]
    ) -> AlertRecord:
        """Store a processed alert in memory."""
        record = AlertRecord(
            alert_id=alert.alert_id,
            attack_id=alert.attack_id,
            attack_name=alert.attack_name or "Unknown",
            tactic=alert.tactic or "Unknown",
            timestamp=alert.timestamp,
            probability=alert.probability,
            threat_level=threat_level,
            source_indicators=alert.observed_indicators,
            actions_taken=actions_taken,
            engage_activities=engage_activities
        )
        
        self._alerts[record.alert_id] = record
        
        # Index by ATT&CK technique
        if alert.attack_id not in self._alerts_by_technique:
            self._alerts_by_technique[alert.attack_id] = []
        self._alerts_by_technique[alert.attack_id].append(record.alert_id)
        
        # Index by tactic
        if alert.tactic:
            if alert.tactic not in self._alerts_by_tactic:
                self._alerts_by_tactic[alert.tactic] = []
            self._alerts_by_tactic[alert.tactic].append(record.alert_id)
        
        # Index by source IP if present
        source_ip = alert.observed_indicators.get("source_ip")
        if source_ip:
            if source_ip not in self._alerts_by_ip:
                self._alerts_by_ip[source_ip] = []
            self._alerts_by_ip[source_ip].append(record.alert_id)
            
            # Update or create attacker profile
            self._update_attacker_profile(source_ip, alert)
        
        return record
    
    def get_alert(self, alert_id: str) -> Optional[AlertRecord]:
        """Retrieve an alert by ID."""
        return self._alerts.get(alert_id)
    
    def get_related_alerts(
        self,
        alert: AlertInput,
        window_hours: int = 4
    ) -> list[AlertRecord]:
        """Find alerts related by technique, tactic, or source IP within time window."""
        related = []
        cutoff = datetime.utcnow() - timedelta(hours=window_hours)
        seen_ids = set()
        
        # Find by same ATT&CK technique
        technique_alerts = self._alerts_by_technique.get(alert.attack_id, [])
        for alert_id in technique_alerts:
            if alert_id in seen_ids:
                continue
            record = self._alerts[alert_id]
            if datetime.fromisoformat(record.timestamp) > cutoff:
                if record.alert_id != alert.alert_id:
                    related.append(record)
                    seen_ids.add(alert_id)
        
        # Find by same tactic
        if alert.tactic:
            tactic_alerts = self._alerts_by_tactic.get(alert.tactic, [])
            for alert_id in tactic_alerts:
                if alert_id in seen_ids:
                    continue
                record = self._alerts[alert_id]
                if datetime.fromisoformat(record.timestamp) > cutoff:
                    if record.alert_id != alert.alert_id:
                        related.append(record)
                        seen_ids.add(alert_id)
        
        # Find by same source IP
        source_ip = alert.observed_indicators.get("source_ip")
        if source_ip:
            ip_alerts = self._alerts_by_ip.get(source_ip, [])
            for alert_id in ip_alerts:
                if alert_id in seen_ids:
                    continue
                record = self._alerts[alert_id]
                if datetime.fromisoformat(record.timestamp) > cutoff:
                    if record.alert_id != alert.alert_id:
                        related.append(record)
                        seen_ids.add(alert_id)
        
        return related
    
    def get_alerts_in_window(
        self,
        hours: int = 24,
        attack_id: Optional[str] = None,
        tactic: Optional[str] = None
    ) -> list[AlertRecord]:
        """Get all alerts within a time window, optionally filtered."""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        results = []
        
        alerts_to_check = self._alerts.values()
        
        if attack_id:
            alert_ids = self._alerts_by_technique.get(attack_id, [])
            alerts_to_check = [self._alerts[aid] for aid in alert_ids]
        elif tactic:
            alert_ids = self._alerts_by_tactic.get(tactic, [])
            alerts_to_check = [self._alerts[aid] for aid in alert_ids]
        
        for record in alerts_to_check:
            if datetime.fromisoformat(record.timestamp) > cutoff:
                results.append(record)
        
        return sorted(results, key=lambda x: x.timestamp, reverse=True)
    
    # ==================== Deployment Operations ====================
    
    def store_deployment(
        self,
        engage_activity_id: str,
        action_type: str,
        location: str,
        alert_id: str,
        attack_id: str
    ) -> Deployment:
        """Store a new deception deployment."""
        deployment = Deployment(
            deployment_id=str(uuid.uuid4()),
            engage_activity_id=engage_activity_id,
            action_type=action_type,
            location=location,
            deployed_at=datetime.utcnow().isoformat(),
            related_alert_id=alert_id,
            attack_id=attack_id,
            triggered=False
        )
        
        self._deployments[deployment.deployment_id] = deployment
        
        # Update indexes
        if location not in self._deployments_by_location:
            self._deployments_by_location[location] = []
        self._deployments_by_location[location].append(deployment.deployment_id)
        
        if attack_id not in self._deployments_by_technique:
            self._deployments_by_technique[attack_id] = []
        self._deployments_by_technique[attack_id].append(deployment.deployment_id)
        
        return deployment
    
    def get_deployments_at_location(self, location: str) -> list[Deployment]:
        """Get all active deployments at a specific location."""
        deployment_ids = self._deployments_by_location.get(location, [])
        return [self._deployments[did] for did in deployment_ids]
    
    def get_deployments_for_technique(self, attack_id: str) -> list[Deployment]:
        """Get all deployments related to an ATT&CK technique."""
        deployment_ids = self._deployments_by_technique.get(attack_id, [])
        return [self._deployments[did] for did in deployment_ids]
    
    def check_redundant_deployment(
        self,
        engage_activity_id: str,
        location: str,
        attack_id: str
    ) -> Optional[Deployment]:
        """Check if a similar deployment already exists."""
        existing = self.get_deployments_at_location(location)
        for deployment in existing:
            if (deployment.engage_activity_id == engage_activity_id and 
                deployment.attack_id == attack_id and
                not deployment.triggered):
                return deployment
        return None
    
    def mark_deployment_triggered(self, deployment_id: str) -> Optional[Deployment]:
        """Mark a deployment as triggered."""
        deployment = self._deployments.get(deployment_id)
        if deployment:
            deployment.triggered = True
            deployment.trigger_count += 1
            deployment.last_triggered_at = datetime.utcnow().isoformat()
        return deployment
    
    # ==================== Attacker Profile Operations ====================
    
    def _update_attacker_profile(
        self,
        source_ip: str,
        alert: AlertInput
    ) -> AttackerProfile:
        """Update or create an attacker profile based on observed activity."""
        profile_id = self._profiles_by_ip.get(source_ip)
        
        if profile_id and profile_id in self._attacker_profiles:
            profile = self._attacker_profiles[profile_id]
            profile.last_seen = datetime.utcnow().isoformat()
            profile.alert_count += 1
            
            # Track techniques
            if alert.attack_id not in profile.observed_techniques:
                profile.observed_techniques.append(alert.attack_id)
            
            # Track tactics and kill chain progress
            if alert.tactic and alert.tactic not in profile.observed_tactics:
                profile.observed_tactics.append(alert.tactic)
                profile.kill_chain_progress.append(alert.tactic)
            
            # Update sophistication estimate
            profile.estimated_sophistication = self._estimate_sophistication(profile)
        else:
            profile = AttackerProfile(
                profile_id=str(uuid.uuid4()),
                associated_ips=[source_ip],
                observed_techniques=[alert.attack_id],
                observed_tactics=[alert.tactic] if alert.tactic else [],
                kill_chain_progress=[alert.tactic] if alert.tactic else []
            )
            self._attacker_profiles[profile.profile_id] = profile
            self._profiles_by_ip[source_ip] = profile.profile_id
        
        return profile
    
    def _estimate_sophistication(self, profile: AttackerProfile) -> str:
        """Estimate attacker sophistication based on observed behavior."""
        technique_count = len(profile.observed_techniques)
        tactic_count = len(profile.observed_tactics)
        
        # More diverse techniques and tactics = higher sophistication
        score = technique_count + (tactic_count * 2)
        
        if score >= 10:
            return "high"
        elif score >= 5:
            return "medium"
        elif score >= 1:
            return "low"
        return "unknown"
    
    def get_attacker_profile_by_ip(self, ip: str) -> Optional[AttackerProfile]:
        """Get attacker profile associated with an IP."""
        profile_id = self._profiles_by_ip.get(ip)
        if profile_id:
            return self._attacker_profiles.get(profile_id)
        return None
    
    # ==================== Pattern Recognition ====================
    
    def detect_attack_escalation(
        self,
        source_ip: str,
        window_hours: int = 24
    ) -> Optional[dict]:
        """Detect if an attacker is progressing through attack phases."""
        profile = self.get_attacker_profile_by_ip(source_ip)
        if not profile or len(profile.observed_tactics) < 2:
            return None
        
        # Get recent alerts from this IP
        cutoff = datetime.utcnow() - timedelta(hours=window_hours)
        recent_alerts = []
        for alert_id in self._alerts_by_ip.get(source_ip, []):
            alert = self._alerts[alert_id]
            if datetime.fromisoformat(alert.timestamp) > cutoff:
                recent_alerts.append(alert)
        
        if len(recent_alerts) < 2:
            return None
        
        # Sort by timestamp
        recent_alerts.sort(key=lambda x: x.timestamp)
        
        # Check for phase progression
        phases_seen = []
        for alert in recent_alerts:
            phase = get_tactic_phase(alert.tactic)
            if phase not in phases_seen:
                phases_seen.append(phase)
        
        # Detect if phases are increasing (escalation)
        is_escalating = phases_seen == sorted(phases_seen) and len(set(phases_seen)) > 1
        
        if is_escalating or len(profile.observed_tactics) >= 3:
            return {
                "attacker_ip": source_ip,
                "profile_id": profile.profile_id,
                "tactics_observed": profile.observed_tactics,
                "techniques_used": profile.observed_techniques,
                "technique_count": len(profile.observed_techniques),
                "sophistication": profile.estimated_sophistication,
                "alert_count": len(recent_alerts),
                "kill_chain_progress": profile.kill_chain_progress,
                "is_escalating": is_escalating
            }
        
        return None
    
    # ==================== Memory Maintenance ====================
    
    def cleanup_old_records(self):
        """Remove records older than retention period."""
        now = datetime.utcnow()
        
        # Cleanup old alerts
        alert_cutoff = now - timedelta(hours=self.config.alert_retention_hours)
        alerts_to_remove = []
        for alert_id, alert in self._alerts.items():
            if datetime.fromisoformat(alert.timestamp) < alert_cutoff:
                alerts_to_remove.append(alert_id)
        
        for alert_id in alerts_to_remove:
            alert = self._alerts.pop(alert_id)
            if alert.attack_id in self._alerts_by_technique:
                self._alerts_by_technique[alert.attack_id] = [
                    a for a in self._alerts_by_technique[alert.attack_id] 
                    if a != alert_id
                ]
            if alert.tactic in self._alerts_by_tactic:
                self._alerts_by_tactic[alert.tactic] = [
                    a for a in self._alerts_by_tactic[alert.tactic]
                    if a != alert_id
                ]
        
        # Cleanup old deployments
        deployment_cutoff = now - timedelta(hours=self.config.deployment_retention_hours)
        deployments_to_remove = []
        for dep_id, dep in self._deployments.items():
            if datetime.fromisoformat(dep.deployed_at) < deployment_cutoff:
                deployments_to_remove.append(dep_id)
        
        for dep_id in deployments_to_remove:
            dep = self._deployments.pop(dep_id)
            if dep.location in self._deployments_by_location:
                self._deployments_by_location[dep.location] = [
                    d for d in self._deployments_by_location[dep.location]
                    if d != dep_id
                ]
    
    def get_memory_summary(self) -> dict:
        """Get a summary of current memory state."""
        return {
            "total_alerts": len(self._alerts),
            "total_deployments": len(self._deployments),
            "total_attacker_profiles": len(self._attacker_profiles),
            "unique_techniques": len(self._alerts_by_technique),
            "unique_tactics": len(self._alerts_by_tactic),
            "unique_source_ips": len(self._alerts_by_ip)
        }

"""
DEMO - DEMO - DEMO - DEMO - DEMO - DEMO - DEMO - DEMO - DEMO - DEMO - DEMO

SCADA Use Case Simulation from Paper:
"A novel proactive and dynamic cyber risk assessment methodology"
(Cheimonidis & Rantos, 2025)

This module simulates the paper's SCADA environment for testing the
cyber deception agent with realistic CVE/ATT&CK data.

DEMO - DEMO - DEMO - DEMO - DEMO - DEMO - DEMO - DEMO - DEMO - DEMO - DEMO
"""

import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime


@dataclass
class Asset:
    """Represents a SCADA asset."""
    name: str
    layer: str  # Enterprise, Industrial, Field
    description: str
    cves: List[str] = field(default_factory=list)
    impact_score: int = 2  # 0-3 scale from paper


@dataclass
class VulnerabilityInfo:
    """Vulnerability information from the paper."""
    cve_id: str
    epss_score: float  # From EPSS
    capec_likelihood: str  # low, medium, high
    capec_numerical: float  # 0.2, 0.5, 0.8
    threat_score: float  # EPSS * CAPEC
    cwe_id: str
    attack_technique: Optional[str] = None  # MITRE ATT&CK ID


# Paper's SCADA Environment Definition
SCADA_ASSETS = {
    "VPN": Asset(
        name="VPN Server",
        layer="Enterprise",
        description="Virtual Private Network for remote access",
        cves=["CVE-2019-11510"],
        impact_score=2
    ),
    "WebS": Asset(
        name="Web Server",
        layer="Enterprise", 
        description="Facility website hosting",
        cves=["CVE-2007-6388"],
        impact_score=2
    ),
    "WS": Asset(
        name="Workstation",
        layer="Enterprise",
        description="Administrative workstation",
        cves=["CVE-2017-0143", "CVE-2017-8692"],
        impact_score=2
    ),
    "HMI": Asset(
        name="Human-Machine Interface",
        layer="Industrial",
        description="SCADA HMI for PLC monitoring",
        cves=["CVE-2011-4875", "CVE-2011-4876", "CVE-2011-4877"],
        impact_score=2
    ),
    "HDB": Asset(
        name="Historical Database",
        layer="Industrial",
        description="SCADA data logging and storage",
        cves=["CVE-2017-8917"],
        impact_score=2
    ),
    "PLC": Asset(
        name="Programmable Logic Controller",
        layer="Field",
        description="Controls actuators and sensors",
        cves=["CVE-2017-7515"],
        impact_score=2
    )
}

# Paper's Vulnerability Data (Table 4, 6, 9)
VULNERABILITIES = {
    "CVE-2019-11510": VulnerabilityInfo(
        cve_id="CVE-2019-11510",
        epss_score=0.974,
        capec_likelihood="high",
        capec_numerical=0.8,
        threat_score=0.779,
        cwe_id="CWE-22",
        attack_technique="T1027"  # Obfuscated Files or Information
    ),
    "CVE-2007-6388": VulnerabilityInfo(
        cve_id="CVE-2007-6388",
        epss_score=0.843,
        capec_likelihood="high",
        capec_numerical=0.8,
        threat_score=0.674,
        cwe_id="CWE-79",
        attack_technique="T1082"  # System Information Discovery
    ),
    "CVE-2017-0143": VulnerabilityInfo(
        cve_id="CVE-2017-0143",
        epss_score=0.960,
        capec_likelihood="high",
        capec_numerical=0.8,
        threat_score=0.768,
        cwe_id="CWE-20",
        attack_technique="T1210"  # Exploitation of Remote Services
    ),
    "CVE-2017-8692": VulnerabilityInfo(
        cve_id="CVE-2017-8692",
        epss_score=0.163,
        capec_likelihood="high",
        capec_numerical=0.8,
        threat_score=0.130,
        cwe_id="CWE-119",
        attack_technique="T1203"  # Exploitation for Client Execution
    ),
    "CVE-2011-4875": VulnerabilityInfo(
        cve_id="CVE-2011-4875",
        epss_score=0.307,
        capec_likelihood="high",
        capec_numerical=0.8,
        threat_score=0.246,
        cwe_id="CWE-119",
        attack_technique="T1059"  # Command and Scripting Interpreter
    ),
    "CVE-2011-4876": VulnerabilityInfo(
        cve_id="CVE-2011-4876",
        epss_score=0.032,
        capec_likelihood="high",
        capec_numerical=0.8,
        threat_score=0.026,
        cwe_id="CWE-22",
        attack_technique="T1083"  # File and Directory Discovery
    ),
    "CVE-2011-4877": VulnerabilityInfo(
        cve_id="CVE-2011-4877",
        epss_score=0.045,
        capec_likelihood="high",
        capec_numerical=0.8,
        threat_score=0.036,
        cwe_id="CWE-20",
        attack_technique="T1499"  # Endpoint Denial of Service
    ),
    "CVE-2017-8917": VulnerabilityInfo(
        cve_id="CVE-2017-8917",
        epss_score=0.976,
        capec_likelihood="high",
        capec_numerical=0.8,
        threat_score=0.780,
        cwe_id="CWE-89",
        attack_technique="T1190"  # Exploit Public-Facing Application
    ),
    "CVE-2017-7515": VulnerabilityInfo(
        cve_id="CVE-2017-7515",
        epss_score=0.114,
        capec_likelihood="high",
        capec_numerical=0.8,
        threat_score=0.091,
        cwe_id="CWE-200",
        attack_technique="T1552"  # Unsecured Credentials
    )
}

# Network topology (attack paths from paper's Bayesian network)
NETWORK_TOPOLOGY = {
    "internet": ["VPN", "WebS"],  # Bridge assets
    "VPN": ["WS"],
    "WebS": ["WS"],
    "WS": ["HMI", "HDB"],
    "HMI": ["PLC"],
    "HDB": ["PLC"]
}

# APT Group indicators from paper (Section 5.1)
APT_INDICATORS = {
    "VPN": {
        "technique": "T1027",
        "total_apt_groups": 15,
        "matching_apt_groups": 3,  # Match Western Europe + Energy
        "indicator_score": 0.3
    },
    "WebS": {
        "technique": "T1082", 
        "total_apt_groups": 46,
        "matching_apt_groups": 9,
        "indicator_score": 0.9
    }
}


class ScadaSimulator:
    """
    Simulates the SCADA environment from the paper for testing
    the cyber deception agent.
    """
    
    def __init__(self):
        self.assets = SCADA_ASSETS
        self.vulnerabilities = VULNERABILITIES
        self.topology = NETWORK_TOPOLOGY
        self.apt_indicators = APT_INDICATORS
        self.target_info = {
            "name": "Western Europe Electric Power Station",
            "industry": "Energy",
            "location": "Western Europe",
            "description": "Government electric facility (paper use case)"
        }
    
    def get_asset(self, asset_name: str) -> Optional[Asset]:
        """Get asset by name."""
        return self.assets.get(asset_name)
    
    def get_vulnerability(self, cve_id: str) -> Optional[VulnerabilityInfo]:
        """Get vulnerability info by CVE ID."""
        return self.vulnerabilities.get(cve_id)
    
    def generate_alert(self, asset_name: str, cve_id: str = None) -> Dict[str, Any]:
        """
        Generate an alert for the deception agent based on 
        a detected attack on an asset.
        """
        asset = self.assets.get(asset_name)
        if not asset:
            raise ValueError(f"Unknown asset: {asset_name}")
        
        # Use specified CVE or pick first from asset
        if cve_id is None:
            cve_id = asset.cves[0] if asset.cves else None
        
        if cve_id is None:
            raise ValueError(f"No CVE available for asset: {asset_name}")
        
        vuln = self.vulnerabilities.get(cve_id)
        if not vuln:
            raise ValueError(f"Unknown CVE: {cve_id}")
        
        # Build alert in the format expected by the agent
        alert = {
            "attack_id": vuln.attack_technique or "T1190",  # Default technique
            "probability": vuln.threat_score,
            "affected_assets": [asset_name],
            "source_ip": "10.0.0.100",  # Simulated attacker IP
            "metadata": {
                "cve_id": cve_id,
                "epss_score": vuln.epss_score,
                "capec_likelihood": vuln.capec_likelihood,
                "asset_layer": asset.layer,
                "impact_score": asset.impact_score
            }
        }
        
        return alert
    
    def simulate_attack_sequence(self) -> List[Dict[str, Any]]:
        """
        Simulate the attack sequence from the paper:
        1. VPN exploitation (entry point)
        2. WebServer exploitation (entry point)
        3. Workstation compromise
        4. Lateral movement to HMI/HDB
        5. PLC access
        """
        alerts = []
        attack_ip = "192.168.1.100"
        
        # Phase 1: Initial Access via VPN
        alerts.append({
            "attack_id": "T1027",  # From paper
            "probability": 0.779,
            "affected_assets": ["VPN"],
            "source_ip": attack_ip,
            "metadata": {
                "cve_id": "CVE-2019-11510",
                "phase": "initial_access",
                "description": "Pulse Secure VPN arbitrary file read"
            }
        })
        
        # Phase 2: WebServer XSS (alternative entry)
        alerts.append({
            "attack_id": "T1082",
            "probability": 0.674,
            "affected_assets": ["WebS"],
            "source_ip": attack_ip,
            "metadata": {
                "cve_id": "CVE-2007-6388",
                "phase": "initial_access",
                "description": "Cross-site scripting via mod_status"
            }
        })
        
        # Phase 3: Workstation compromise (EternalBlue)
        alerts.append({
            "attack_id": "T1210",
            "probability": 0.768,
            "affected_assets": ["WS"],
            "source_ip": attack_ip,
            "metadata": {
                "cve_id": "CVE-2017-0143",
                "phase": "lateral_movement",
                "description": "SMBv1 remote code execution (EternalBlue)"
            }
        })
        
        # Phase 4: HMI compromise
        alerts.append({
            "attack_id": "T1059",
            "probability": 0.246,
            "affected_assets": ["HMI"],
            "source_ip": attack_ip,
            "metadata": {
                "cve_id": "CVE-2011-4875",
                "phase": "industrial_access",
                "description": "HMI arbitrary code execution"
            }
        })
        
        # Phase 5: Database compromise
        alerts.append({
            "attack_id": "T1190",
            "probability": 0.780,
            "affected_assets": ["HDB"],
            "source_ip": attack_ip,
            "metadata": {
                "cve_id": "CVE-2017-8917",
                "phase": "industrial_access",
                "description": "SQL injection in Joomla CMS"
            }
        })
        
        # Phase 6: PLC access (final target)
        alerts.append({
            "attack_id": "T1552",
            "probability": 0.091,
            "affected_assets": ["PLC"],
            "source_ip": attack_ip,
            "metadata": {
                "cve_id": "CVE-2017-7515",
                "phase": "impact",
                "description": "Password discovery on PLC"
            }
        })
        
        return alerts
    
    def get_scenario_info(self) -> Dict[str, Any]:
        """Get information about the simulation scenario."""
        return {
            "name": "SCADA Risk Assessment Use Case",
            "source": "Cheimonidis & Rantos (2025)",
            "paper": "A novel proactive and dynamic cyber risk assessment methodology",
            "target": self.target_info,
            "assets": {
                name: {
                    "layer": asset.layer,
                    "cves": asset.cves,
                    "impact_score": asset.impact_score
                }
                for name, asset in self.assets.items()
            },
            "attack_phases": [
                "Initial Access (VPN/WebServer)",
                "Lateral Movement (Workstation)",
                "Industrial Access (HMI/HDB)",
                "Impact (PLC)"
            ],
            "total_cves": len(self.vulnerabilities),
            "bridge_assets": ["VPN", "WebS"]
        }
    
    def print_scenario(self):
        """Print a summary of the scenario."""
        print("\n" + "="*60)
        print("SCADA CYBER DECEPTION SCENARIO")
        print("Based on: Cheimonidis & Rantos (2025)")
        print("="*60)
        print(f"\nTarget: {self.target_info['name']}")
        print(f"Industry: {self.target_info['industry']}")
        print(f"Location: {self.target_info['location']}")
        
        print("\n--- Network Assets ---")
        for layer in ["Enterprise", "Industrial", "Field"]:
            print(f"\n{layer} Layer:")
            for name, asset in self.assets.items():
                if asset.layer == layer:
                    print(f"  {name}: {asset.description}")
                    for cve in asset.cves:
                        vuln = self.vulnerabilities.get(cve)
                        if vuln:
                            print(f"    - {cve} (EPSS: {vuln.epss_score:.3f}, "
                                  f"Threat: {vuln.threat_score:.3f}, "
                                  f"ATT&CK: {vuln.attack_technique})")
        
        print("\n--- Attack Path ---")
        print("Internet → [VPN or WebS] → WS → [HMI/HDB] → PLC")
        
        print("\n--- APT Indicators ---")
        for asset, info in self.apt_indicators.items():
            print(f"  {asset}: {info['matching_apt_groups']}/{info['total_apt_groups']} "
                  f"APT groups (score: {info['indicator_score']})")


def run_demo():
    """Run a demo of the SCADA simulator."""
    sim = ScadaSimulator()
    sim.print_scenario()
    
    print("\n" + "="*60)
    print("SIMULATED ATTACK SEQUENCE")
    print("="*60)
    
    alerts = sim.simulate_attack_sequence()
    for i, alert in enumerate(alerts, 1):
        print(f"\n[Alert {i}] {alert['metadata'].get('phase', 'unknown').upper()}")
        print(f"  ATT&CK: {alert['attack_id']}")
        print(f"  Target: {alert['affected_assets']}")
        print(f"  Probability: {alert['probability']:.3f}")
        print(f"  CVE: {alert['metadata'].get('cve_id')}")
        print(f"  Description: {alert['metadata'].get('description')}")


if __name__ == "__main__":
    run_demo()

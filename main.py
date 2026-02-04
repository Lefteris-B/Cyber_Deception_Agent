#!/usr/bin/env python3
"""
Cyber Deception Agent - CLI Entry Point

Uses MITRE ATT&CK for threat input and MITRE Engage for deception response.

Usage:
    python main.py                    # Interactive mode
    python main.py --alert '{"attack_id": "T1003", "probability": 0.85}'
    python main.py --no-llm           # Rule-based mode
"""

import argparse
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agent import CyberDeceptionAgent, format_action_plan, export_action_plan_json
from schemas import AlertInput
from config import AgentConfig, ATTACK_TACTICS_ORDER


def parse_args():
    parser = argparse.ArgumentParser(
        description="Cyber Deception Agent - ATT&CK + Engage Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                                    # Interactive mode
  python main.py --alert '{"attack_id": "T1003", "probability": 0.85}'
  python main.py --file alert.json --output plan.json
  python main.py --no-llm                           # Rule-based mode
  python main.py --status                           # Show agent status
        """
    )
    
    parser.add_argument(
        "--alert", "-a",
        type=str,
        help="Alert JSON string to process"
    )
    
    parser.add_argument(
        "--file", "-f",
        type=str,
        help="Path to alert JSON file"
    )
    
    parser.add_argument(
        "--output", "-o",
        type=str,
        help="Output file for action plan JSON"
    )
    
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Use rule-based engine instead of LLM"
    )
    
    parser.add_argument(
        "--data-path",
        type=str,
        default=None,  # Will use config default if not specified
        help="Path to Engage data file (default: auto-detect)"
    )
    
    parser.add_argument(
        "--status",
        action="store_true",
        help="Show agent status and exit"
    )
    
    parser.add_argument(
        "--list-techniques",
        action="store_true",
        help="List available ATT&CK technique mappings"
    )
    
    parser.add_argument(
        "--scada",
        action="store_true",
        help="Run SCADA use case from paper (Cheimonidis & Rantos, 2025)"
    )
    
    return parser.parse_args()


def create_alert_from_dict(data: dict) -> AlertInput:
    """Create AlertInput from dictionary."""
    return AlertInput(
        attack_id=data.get("attack_id", "T0000"),
        probability=data.get("probability", 0.5),
        alert_id=data.get("alert_id"),
        timestamp=data.get("timestamp"),
        attack_name=data.get("attack_name"),
        tactic=data.get("tactic"),
        affected_assets=data.get("affected_assets", []),
        observed_indicators=data.get("observed_indicators", {})
    )


def interactive_mode(agent: CyberDeceptionAgent):
    """Run agent in interactive mode."""
    print("\n" + "="*60)
    print("CYBER DECEPTION AGENT - ATT&CK + Engage")
    print("="*60)
    print("\nCommands:")
    print("  alert     - Process a new ATT&CK-based alert")
    print("  status    - Show agent status")
    print("  memory    - Show memory summary")
    print("  techniques- List available ATT&CK techniques")
    print("  trigger   - Report a deployment was triggered")
    print("  help      - Show this help")
    print("  quit      - Exit")
    print()
    
    while True:
        try:
            command = input("\n> ").strip().lower()
            
            if command in ["quit", "exit", "q"]:
                print("Goodbye!")
                break
            
            elif command == "help":
                print("Commands: alert, status, memory, techniques, trigger, help, quit")
            
            elif command == "status":
                status = agent.get_status()
                print(json.dumps(status, indent=2))
            
            elif command == "memory":
                if agent.memory:
                    print(json.dumps(agent.memory.get_memory_summary(), indent=2))
                else:
                    print("Memory not initialized")
            
            elif command == "techniques":
                if agent.engage_loader:
                    techniques = agent.engage_loader.list_all_techniques()
                    print(f"\nAvailable ATT&CK techniques ({len(techniques)}):")
                    for tech in techniques[:20]:
                        print(f"  {tech['attack_id']}: {tech['name']}")
                        print(f"    Tactics: {', '.join(tech['tactics'])}")
                        print(f"    Engage: {tech['engage_activities']}")
                    if len(techniques) > 20:
                        print(f"  ... and {len(techniques) - 20} more")
                else:
                    print("Engage loader not initialized")
            
            elif command == "alert":
                print("\nEnter alert details:")
                attack_id = input("  ATT&CK Technique ID (e.g., T1003): ").strip()
                prob_str = input("  Probability (0.0-1.0): ").strip()
                assets_str = input("  Affected assets (comma-separated, or empty): ").strip()
                source_ip = input("  Source IP (or empty): ").strip()
                
                try:
                    probability = float(prob_str)
                except ValueError:
                    probability = 0.5
                    print(f"  Invalid probability, using {probability}")
                
                assets = [a.strip() for a in assets_str.split(",") if a.strip()]
                indicators = {}
                if source_ip:
                    indicators["source_ip"] = source_ip
                
                alert = AlertInput(
                    attack_id=attack_id,
                    probability=probability,
                    affected_assets=assets,
                    observed_indicators=indicators
                )
                
                plan = agent.process_alert(alert)
                print(format_action_plan(plan))
            
            elif command == "trigger":
                dep_id = input("  Deployment ID: ").strip()
                if agent.report_deployment_triggered(dep_id):
                    print("  ✓ Deployment marked as triggered")
                else:
                    print("  ✗ Deployment not found")
            
            else:
                print(f"Unknown command: {command}")
                print("Type 'help' for available commands")
        
        except KeyboardInterrupt:
            print("\nGoodbye!")
            break
        except Exception as e:
            print(f"Error: {e}")


def run_scada_scenario(agent: CyberDeceptionAgent):
    """Run the SCADA use case from the paper."""
    try:
        from scada_usecase import ScadaSimulator
    except ImportError:
        print("Error: scada_usecase.py not found")
        return
    
    sim = ScadaSimulator()
    sim.print_scenario()
    
    print("\n" + "="*60)
    print("PROCESSING ATTACK SEQUENCE WITH DECEPTION AGENT")
    print("="*60)
    
    alerts = sim.simulate_attack_sequence()
    for i, alert_data in enumerate(alerts, 1):
        print(f"\n{'='*60}")
        print(f"[PHASE {i}] {alert_data['metadata'].get('phase', '').upper()}")
        print(f"{'='*60}")
        print(f"CVE: {alert_data['metadata'].get('cve_id')}")
        print(f"ATT&CK: {alert_data['attack_id']}")
        print(f"Target: {alert_data['affected_assets']}")
        print(f"Threat Score: {alert_data['probability']:.3f}")
        
        alert = AlertInput(
            attack_id=alert_data["attack_id"],
            probability=alert_data["probability"],
            affected_assets=alert_data["affected_assets"],
            observed_indicators={"source_ip": alert_data.get("source_ip", "unknown")}
        )
        
        response = agent.process_alert(alert)
        print(f"\n--- Deception Response ---")
        print(f"Threat Level: {response.threat_level.upper()}")
        print(f"Actions Recommended: {len(response.recommended_actions)}")
        for action in response.recommended_actions:
            print(f"  • [{action.engage_activity_id}] {action.action_type}")
            print(f"    Target: {action.parameters.get('target_systems', action.parameters.get('placement', 'N/A'))}")
            if action.rationale:
                desc = action.rationale[:60] + "..." if len(action.rationale) > 60 else action.rationale
                print(f"    Purpose: {desc}")
        
        if i < len(alerts):
            try:
                input("\nPress Enter to continue to next phase... ")
            except EOFError:
                pass
    
    print("\n" + "="*60)
    print("ATTACK SEQUENCE COMPLETE - FINAL MEMORY STATE")
    print("="*60)
    if agent.memory:
        summary = agent.memory.get_memory_summary()
        print(json.dumps(summary, indent=2))
    
    # Show escalation detection
    if agent.memory:
        escalation = agent.memory.detect_attack_escalation()
        if escalation:
            print("\n⚠️  ATTACK ESCALATION DETECTED")
            print(f"   Stages observed: {escalation.get('stages', [])}")


def main():
    args = parse_args()
    
    # Configure agent
    config = AgentConfig()
    if args.data_path:
        config.engage_data_path = args.data_path
    
    # Initialize agent
    use_llm = not args.no_llm
    if not use_llm:
        print("Using rule-based decision engine (no LLM)")
    
    agent = CyberDeceptionAgent(config=config, use_llm=use_llm)
    
    if not agent.initialize():
        print("Failed to initialize agent")
        sys.exit(1)
    
    # Show status and exit if requested
    if args.status:
        print(json.dumps(agent.get_status(), indent=2))
        return
    
    # List techniques and exit if requested
    if args.list_techniques:
        techniques = agent.engage_loader.list_all_techniques()
        print(f"\nATT&CK Techniques with Engage mappings ({len(techniques)}):\n")
        for tech in techniques:
            print(f"  {tech['attack_id']}: {tech['name']}")
            print(f"    Tactics: {', '.join(tech['tactics'])}")
            print(f"    Engage activities: {tech['engage_activities']}")
        return
    
    # Run SCADA scenario if requested
    if args.scada:
        run_scada_scenario(agent)
        return
    
    # Process alert from command line
    if args.alert:
        try:
            alert_data = json.loads(args.alert)
            alert = create_alert_from_dict(alert_data)
            plan = agent.process_alert(alert)
            print(format_action_plan(plan))
            
            if args.output:
                export_action_plan_json(plan, args.output)
        except json.JSONDecodeError as e:
            print(f"Invalid JSON: {e}")
            sys.exit(1)
        return
    
    # Process alert from file
    if args.file:
        try:
            with open(args.file, 'r') as f:
                alert_data = json.load(f)
            alert = create_alert_from_dict(alert_data)
            plan = agent.process_alert(alert)
            print(format_action_plan(plan))
            
            if args.output:
                export_action_plan_json(plan, args.output)
        except FileNotFoundError:
            print(f"File not found: {args.file}")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"Invalid JSON in file: {e}")
            sys.exit(1)
        return
    
    # Interactive mode
    interactive_mode(agent)


if __name__ == "__main__":
    main()

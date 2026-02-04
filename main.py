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
        "--cleanup",
        action="store_true",
        help="Cleanup agent memory and exit"
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
    print("  cleanup   - Cleanup memory")
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
                print("Commands: alert, status, memory, cleanup, techniques, trigger, help, quit")
            
            elif command == "status":
                status = agent.get_status()
                print(json.dumps(status, indent=2))
            
            elif command == "memory":
                if agent.memory:
                    print(json.dumps(agent.memory.get_memory_summary(), indent=2))
                else:
                    print("Memory not initialized")

            elif command == "cleanup":
                agent.cleanup_memory()

            elif command == "techniques":
                if agent.engage_loader:
                    attack_ids = agent.engage_loader.get_all_attack_ids()
                    print(f"\nAvailable ATT&CK techniques ({len(attack_ids)}):")
                    for attack_id in sorted(attack_ids)[:20]:
                        mapping = agent.engage_loader.get_attack_mapping(attack_id)
                        if mapping:
                            print(f"  {attack_id}: {mapping.attack_name} ({mapping.tactic})")
                    if len(attack_ids) > 20:
                        print(f"  ... and {len(attack_ids) - 20} more")
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
        attack_ids = agent.engage_loader.get_all_attack_ids()
        print(f"\nATT&CK Techniques with Engage mappings ({len(attack_ids)}):\n")
        for attack_id in sorted(attack_ids):
            mapping = agent.engage_loader.get_attack_mapping(attack_id)
            if mapping:
                activities = agent.engage_loader.get_activities_for_technique(attack_id)
                print(f"  {attack_id}: {mapping.attack_name}")
                print(f"    Tactic: {mapping.tactic}")
                print(f"    Engage activities: {[a.id for a in activities]}")
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
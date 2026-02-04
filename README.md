# Cyber Deception Agent

An AI-powered agent that analyzes threat alerts using **MITRE ATT&CK** and recommends defensive deception actions using **MITRE Engage** to mislead, slow, and gather intelligence on attackers.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    CYBER DECEPTION AGENT                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
│  │   INTAKE    │───▶│  DECISION   │───▶│   OUTPUT    │     │
│  │   (Alert)   │    │   ENGINE    │    │   (Plan)    │     │
│  └─────────────┘    └─────────────┘    └─────────────┘     │
│         │                 │                   │             │
│         ▼                 ▼                   ▼             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
│  │   MEMORY    │◀──▶│  PLAYBOOKS  │    │  ACTIONS    │     │
│  │   (State)   │    │   (JSON)    │    │  (Deception)│     │
│  └─────────────┘    └─────────────┘    └─────────────┘     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Components

| File | Purpose |
|------|---------|
| `agent.py` | Main orchestrator that coordinates all components |
| `decision_engine.py` | LLM-based and rule-based decision making |
| `memory.py` | In-memory storage for alerts, deployments, attacker profiles |
| `playbook_loader.py` | Loads and indexes JSON playbooks by CAPEC ID |
| `schemas.py` | Data models for inputs, outputs, and internal state |
| `config.py` | Configuration, thresholds, and threat level strategies |
| `main.py` | CLI entry point |

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Set API Key (for LLM mode)

```bash
export ANTHROPIC_API_KEY="your-api-key"
```

### 3. Create Sample Playbooks

```bash
python main.py --create-samples
```

### 4. Run the Agent

```bash
# Interactive mode
python main.py

# Process a single alert
python main.py --alerts '{"capec_id": "CAPEC-98", "probability": 0.85, "affected_assets": ["endpoint-01"]}'

# Rule-based mode (no LLM)
python main.py --no-llm
```

## Input Format

The agent accepts alerts in this format:

```json
{
  "capec_id": "CAPEC-98",
  "probability": 0.85,
  "alert_id": "optional-uuid",
  "affected_assets": ["endpoint-win-042", "user:jsmith"],
  "observed_indicators": {
    "source_ip": "203.0.113.50",
    "target": "internal-fileserver-01"
  },
  "attack_phase": "initial_access"
}
```

## Output Format

The agent produces action plans:

```json
{
  "alert_id": "uuid",
  "capec_id": "CAPEC-98",
  "threat_level": "high",
  "recommended_actions": [
    {
      "action_id": "phish-honey-1",
      "action_type": "deploy_honeytoken",
      "priority": "high",
      "parameters": {
        "token_type": "credential",
        "placement": "endpoint-win-042"
      },
      "rationale": "Plant fake credentials for detection"
    }
  ],
  "deception_objective": "detect_lateral_movement",
  "confidence": 0.82,
  "reasoning": "High probability phishing attack..."
}
```

## Threat Levels

| Level | Probability | Response |
|-------|-------------|----------|
| LOW | 0.0 - 0.39 | Passive honeytokens |
| MEDIUM | 0.4 - 0.69 | Active decoys and breadcrumbs |
| HIGH | 0.7 - 0.89 | Multiple deception layers |
| CRITICAL | 0.9 - 1.0 | Full engagement, tarpitting |

## Playbook Format

Playbooks are JSON files mapping CAPEC IDs to deception actions:

```json
{
  "capec_id": "CAPEC-98",
  "capec_name": "Phishing",
  "attack_phase": "initial_access",
  "actions": [
    {
      "action_id": "phish-honey-1",
      "action_type": "deploy_honeytoken",
      "min_threat_level": "low",
      "priority": "high",
      "parameters": {
        "token_type": "credential",
        "placement": "{{affected_asset}}"
      },
      "rationale": "Detect credential harvesting"
    }
  ]
}
```

### Template Variables

Use these in playbook parameters for dynamic substitution:
- `{{affected_asset}}` - Replaced with actual affected asset
- `{{source_ip}}` - Replaced with attacker's source IP
- `{{source_network}}` - Replaced with source network segment

## Memory System

The agent maintains memory of:

- **Alert History**: Past alerts for correlation and pattern detection
- **Active Deployments**: Deployed deception assets to avoid redundancy
- **Attacker Profiles**: Built from observed source IPs and techniques

Memory enables:
- Detecting attack escalation (progression through kill chain)
- Avoiding redundant deployments
- Estimating attacker sophistication
- Correlating related alerts

## Extending the Agent

### Adding New Playbooks

1. Create a JSON file in `./playbooks/`
2. Follow the playbook schema (see sample playbooks)
3. Map to CAPEC ID
4. Define actions with appropriate threat level thresholds

### Custom Decision Logic

Extend `DecisionEngine` in `decision_engine.py` to customize:
- Action selection criteria
- Parameter adaptation logic
- Confidence scoring

### Persistent Memory

Replace `AgentMemory` with a database-backed implementation for production use.

## Integration Points

The agent is designed to integrate with:

- **Input**: SIEM, threat intelligence platforms, detection systems
- **Output**: SOAR platforms, deception infrastructure (honeypots, etc.)

The output JSON can be consumed by automation systems to deploy actual deception assets.

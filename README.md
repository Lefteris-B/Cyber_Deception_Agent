# Cyber Deception Agent

An AI-powered agent that analyzes threat alerts using **MITRE ATT&CK** and recommends defensive deception actions using **MITRE Engage** to mislead, slow, and gather intelligence on attackers.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    CYBER DECEPTION AGENT                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐      │
│  │   INTAKE    │───▶│  DECISION   │───▶│   OUTPUT    │      │
│  │   (Alert)   │    │   ENGINE    │    │   (Plan)    │      │
│  └─────────────┘    └─────────────┘    └─────────────┘      │
│         │                 │                   │             │
│         ▼                 ▼                   ▼             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐      │
│  │   MEMORY    │◀──▶│  PLAYBOOKS  │    │  ACTIONS    │      │
│  │   (State)   │    │   (JSON)    │    │  (Deception)│      │
│  └─────────────┘    └─────────────┘    └─────────────┘      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```
For more information please read the  [Onboarding guide](/doc/Dev_Onboarding_Guide.pdf)

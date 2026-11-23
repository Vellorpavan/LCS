---
name: call-me
description: Explicit entry point into the Living Capability System (LCS) universal multi-agent intelligence and capability orchestration engine.
category: orchestration
---
<!-- LCS-MANAGED-COMMAND-ARTIFACT -->

# /call-me — Living Capability System Entry Point

When the user invokes `/call-me <task>`, activate LCS to discover, evaluate, retrieve, plan, and govern capabilities across Antigravity, Claude Code, OpenCode, and local tools.

## Invocation Syntax
`/call-me <natural language task description>`

## Execution Flow
1. Receives the user's natural language task description.
2. Performs fast cache-assisted discovery across authorized skills and MCP servers.
3. Understands input parameters and synthesizes a verifiable DAG plan.
4. Submits the plan to LCS Governance Engine (Gate 1 & Gate 2) prior to execution.

## Execution Command
```bash
lcs call-me "$*"
```

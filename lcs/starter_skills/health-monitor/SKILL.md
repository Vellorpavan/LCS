---
name: health-monitor
description: Build health check probes, uptime monitors, dependency status checkers, and diagnostics endpoints.
---

# Health Monitoring & Diagnostics Skill

## Purpose
Constructs modular health monitoring services, liveness probes, readiness checks, and uptime tracking.

## Guidelines
1. Check process liveness, process uptime, memory consumption, and disk space availability.
2. Probe dependent services and databases with timeout guards to prevent cascade blocks.
3. Return standard HTTP/JSON health payloads (`status`: "healthy" | "degraded" | "unhealthy").
4. Provide structured diagnostic summaries for operational observability.

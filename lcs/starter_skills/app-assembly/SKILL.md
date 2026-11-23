---
name: app-assembly
description: Assemble modular services, coordinate runners, configure application lifecycles, and wire service entrypoints.
---

# Application Assembly & Runner Skill

## Purpose
Integrates individual service modules into a unified application lifecycle and executable entry point.

## Guidelines
1. Import and wire together domain services (e.g. telemetry, health monitors, database adapters).
2. Manage graceful startup and teardown sequences (closing DB connections, flushing telemetry).
3. Expose CLI or programmatic runners (`main()` / `run()`) that coordinate subcomponents.
4. Return aggregate execution status and logs for verification.

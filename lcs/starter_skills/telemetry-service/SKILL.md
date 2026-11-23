---
name: telemetry-service
description: Build SQLite or file-backed telemetry ingestion, metric counters, event logging, and aggregation services.
---

# Telemetry Service Builder Skill

## Purpose
Authors lightweight, reliable telemetry ingestion systems, metric tracking, and event buffers.

## Guidelines
1. Ingest metrics such as latencies, counters, system events, and error rates.
2. Provide deterministic persistence using SQLite transactions or structured JSONL streams.
3. Expose clean query functions for metric summarization and time-window rollups.
4. Guarantee atomic commits and resilient error handling for corrupt records.

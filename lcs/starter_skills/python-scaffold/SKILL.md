---
name: python-scaffold
description: Scaffold clean modern Python projects with standard layouts, pyproject.toml, virtual environments, and entry points.
---

# Python Project Scaffolding Skill

## Purpose
Provides end-to-end scaffolding for modern, production-ready Python applications and services.

## Guidelines
1. Create standard layout:
   - `src/` for application packages and business modules.
   - `tests/` for unit, integration, and regression test suites.
   - `pyproject.toml` or `requirements.txt` declaring dependencies.
2. Ensure clean separation of concerns between domain logic, data persistence, and interface adapters.
3. Include clear entrypoints and executable modules with `if __name__ == '__main__':` guards.

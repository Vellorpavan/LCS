"""
LCS Invocation Interface & Entry Point Package (Phase 2A)
=========================================================
Exports:
- TaskRequest, InvocationResponse, ConsentState: Structured request contracts
- LCSCoreBridge: Bridge handing off requests to LCS Core intelligence
- CallMeInterface, CallMeError: Thin /call-me entry point with dormancy gate
- SlashCommandGenerator, CommandGeneratorError: Host slash-command generators
"""

from .contract import (
    ConsentState,
    TaskRequest,
    InvocationResponse,
)
from .core_bridge import LCSCoreBridge
from .entry_point import (
    CallMeInterface,
    CallMeError,
)
from .generators import (
    SlashCommandGenerator,
    CommandGeneratorError,
)

__all__ = [
    "ConsentState",
    "TaskRequest",
    "InvocationResponse",
    "LCSCoreBridge",
    "CallMeInterface",
    "CallMeError",
    "SlashCommandGenerator",
    "CommandGeneratorError",
]

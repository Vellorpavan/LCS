"""
LCS Environment Capability Negotiation Engine
=============================================
Evaluates an active host adapter's declared capabilities and determines the
optimal handoff, execution, and consent channels for a given task.

Supports:
- CLI (Universal baseline)
- MCP (Model Context Protocol stdio/SSE)
- Slash Command / Skill Macro Manifests
- Autonomous Subagent Delegation
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional

from .base import EnvironmentAdapter, AdapterFeature


class NegotiatedChannel(str, Enum):
    """Available interaction and handoff channels with a host agent."""
    SUBAGENT      = "subagent"
    SLASH_COMMAND = "slash_command"
    MCP           = "mcp"
    CLI           = "cli"


class ConsentMechanism(str, Enum):
    """Mechanism for acquiring operator approval before execution."""
    TTY   = "tty"
    MODAL = "modal"
    NONE  = "none"


@dataclass(frozen=True)
class CapabilityNegotiationResult:
    """Outcome of capability negotiation between LCS and the host agent."""
    adapter_id: str
    environment_kind: str
    supported_channels: List[NegotiatedChannel]
    preferred_channel: NegotiatedChannel
    fallback_channels: List[NegotiatedChannel]
    can_stream_traces: bool = False
    consent_mechanism: ConsentMechanism = ConsentMechanism.NONE
    mcp_supported: bool = False
    subagent_supported: bool = False

    def is_channel_supported(self, channel: NegotiatedChannel) -> bool:
        return channel in self.supported_channels


class CapabilityNegotiator:
    """
    Determines the best interaction channel based on adapter features and task requirements.
    """

    @classmethod
    def negotiate(
        cls,
        adapter: EnvironmentAdapter,
        task_hints: Optional[Dict[str, Any]] = None
    ) -> CapabilityNegotiationResult:
        """
        Negotiates active channels for the provided adapter.
        CLI is universally supported as the deterministic fallback.
        """
        hints = task_hints or {}
        supported: List[NegotiatedChannel] = []

        # 1. Evaluate features
        has_subagent = adapter.has_feature(AdapterFeature.AGENT_DELEGATION)
        has_slash = adapter.has_feature(AdapterFeature.SLASH_COMMAND_REGISTRATION) or adapter.has_feature(AdapterFeature.COMMAND_DISCOVERY)
        has_mcp = adapter.has_feature(AdapterFeature.MCP_TOOL_INVOCATION) or adapter.has_feature(AdapterFeature.MCP_CONFIG_DISCOVERY)

        if has_subagent:
            supported.append(NegotiatedChannel.SUBAGENT)
        if has_slash:
            supported.append(NegotiatedChannel.SLASH_COMMAND)
        if has_mcp:
            supported.append(NegotiatedChannel.MCP)
        supported.append(NegotiatedChannel.CLI)  # Always supported

        # 2. Determine Preferred Channel
        explicit_pref = hints.get("preferred_channel")
        preferred: NegotiatedChannel

        if explicit_pref and isinstance(explicit_pref, str):
            try:
                cand = NegotiatedChannel(explicit_pref.lower())
                if cand in supported:
                    preferred = cand
                else:
                    preferred = cls._default_preferred(adapter, supported, hints)
            except ValueError:
                preferred = cls._default_preferred(adapter, supported, hints)
        else:
            preferred = cls._default_preferred(adapter, supported, hints)

        fallbacks = [c for c in supported if c != preferred]

        # 3. Consent Mechanism
        consent = ConsentMechanism.NONE
        if adapter.has_feature(AdapterFeature.INTERACTIVE_TTY_CONSENT):
            consent = ConsentMechanism.TTY
        elif adapter.has_feature(AdapterFeature.CONVERSATIONAL_MODAL_CONSENT):
            consent = ConsentMechanism.MODAL

        can_stream = adapter.has_feature(AdapterFeature.EXECUTION_TRACE_STREAMING)

        env_kind = (
            adapter.environment_kind.value
            if hasattr(adapter.environment_kind, "value")
            else str(adapter.environment_kind)
        )

        return CapabilityNegotiationResult(
            adapter_id=adapter.adapter_id,
            environment_kind=env_kind,
            supported_channels=supported,
            preferred_channel=preferred,
            fallback_channels=fallbacks,
            can_stream_traces=can_stream,
            consent_mechanism=consent,
            mcp_supported=has_mcp,
            subagent_supported=has_subagent
        )

    @classmethod
    def _default_preferred(
        cls,
        adapter: EnvironmentAdapter,
        supported: List[NegotiatedChannel],
        hints: Dict[str, Any]
    ) -> NegotiatedChannel:
        """Determines default preferred channel based on priority hierarchy."""
        # For Generic POSIX CLI adapter, CLI is the primary interaction surface
        env_kind = str(adapter.environment_kind.value if hasattr(adapter.environment_kind, "value") else adapter.environment_kind).lower()
        if env_kind == "generic_posix":
            return NegotiatedChannel.CLI

        # If task explicitly requires autonomous delegation and host supports it
        if hints.get("requires_delegation") and NegotiatedChannel.SUBAGENT in supported:
            return NegotiatedChannel.SUBAGENT

        # Slash command provides native interactive entry point
        if NegotiatedChannel.SLASH_COMMAND in supported:
            return NegotiatedChannel.SLASH_COMMAND

        # MCP tool invocation for tool-centric environments
        if NegotiatedChannel.MCP in supported:
            return NegotiatedChannel.MCP

        # Subagent delegation
        if NegotiatedChannel.SUBAGENT in supported:
            return NegotiatedChannel.SUBAGENT

        # Universal fallback
        return NegotiatedChannel.CLI

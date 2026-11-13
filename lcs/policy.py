"""
LCS Interface Policy Package Wrapper
"""

import os
import sys

_PARENT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from interface_policy_v2b import (
    InterfaceDeclaration,
    InterfaceAttestation,
    InterfaceTrustPolicy,
    PolicyEvaluationDecision,
    InterfacePolicyService,
    InterfaceCapabilityRef,
    InterfacePolicyError,
    AttestationVerificationError,
    InvalidInterfaceDeclarationError,
    InvalidInterfaceURNError,
    CapabilityNotFoundError,
    InterfaceNotFoundError,
    AgentNotFoundError,
    PolicyEvaluationError
)

__all__ = [
    "InterfaceDeclaration",
    "InterfaceAttestation",
    "InterfaceTrustPolicy",
    "PolicyEvaluationDecision",
    "InterfacePolicyService",
    "InterfaceCapabilityRef",
    "InterfacePolicyError",
    "AttestationVerificationError",
    "InvalidInterfaceDeclarationError",
    "InvalidInterfaceURNError",
    "CapabilityNotFoundError",
    "InterfaceNotFoundError",
    "AgentNotFoundError",
    "PolicyEvaluationError",
]

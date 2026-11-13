#!/usr/bin/env python3
"""
LCS Stage 2B — Capability Parameter Understanding V1
====================================================
Transforms natural-language and structured requests into validated,
evidence-grounded capability parameter bindings.

Architecture Layer:
  Directly above Capability Semantic Profiles and Capability Retrieval V1.1.
  Evaluates the input requirements of a retrieved or target capability,
  maps explicit user-provided arguments, checks constraints and types,
  identifies missing parameters, and issues actionable readiness verdicts.

Readiness Statuses:
  - READY:        All required parameters are validly mapped and satisfied.
  - INCOMPLETE:   One or more required parameters are missing.
  - INVALID:      Supplied parameter values violate types, constraints, or bounds.
  - INCOMPATIBLE: The request cannot be represented by the capability schema
                  (e.g. unknown schema, zero-parameter mismatch, or conflicting interface).
"""

import os
import re
import sys
import json
from typing import Dict, Any, List, Optional, Tuple, Set, Union

from capability_profile_v2b import (
    EvidenceSource,
    ProfileField,
    ParameterProfile,
    CapabilitySemanticProfile,
    CapabilityProfileService
)
from capability_registry_v2b import parse_canonical_urn, CanonicalCapabilityURN


# ----------------------------------------------------------------------------
# Enums and Constants
# ----------------------------------------------------------------------------

class ParameterReadinessStatus:
    READY = "READY"
    INCOMPLETE = "INCOMPLETE"
    INVALID = "INVALID"
    INCOMPATIBLE = "INCOMPATIBLE"


VALID_READINESS_STATUSES = frozenset({
    ParameterReadinessStatus.READY,
    ParameterReadinessStatus.INCOMPLETE,
    ParameterReadinessStatus.INVALID,
    ParameterReadinessStatus.INCOMPATIBLE
})


class MappingMethod:
    EXPLICIT_KEY_VALUE = "EXPLICIT_KEY_VALUE"
    EXPLICIT_JSON = "EXPLICIT_JSON"
    EXPLICIT_CLI_FLAG = "EXPLICIT_CLI_FLAG"
    PATTERN_EXTRACTION = "PATTERN_EXTRACTION"
    SEMANTIC_MATCH = "SEMANTIC_MATCH"
    DEFAULT_VALUE = "DEFAULT_VALUE"


# ----------------------------------------------------------------------------
# Data Models: ParameterRequirement, MappedParameter, ParameterReadinessResult
# ----------------------------------------------------------------------------

class ParameterRequirement:
    """
    Formal representation of an input parameter expected by a capability,
    preserving types, constraints, defaults, and evidence.
    """
    def __init__(
        self,
        name: str,
        param_type: str,
        required: bool,
        description: Optional[str] = None,
        default: Any = None,
        enum: Optional[List[Any]] = None,
        minimum: Optional[Union[int, float]] = None,
        maximum: Optional[Union[int, float]] = None,
        pattern: Optional[str] = None,
        item_type: Optional[str] = None,
        evidence: str = EvidenceSource.EXTRACTED,
        notes: str = ""
    ):
        self.name = name
        self.param_type = param_type or "any"
        self.required = required
        self.description = description
        self.default = default
        self.enum = list(enum) if enum is not None else None
        self.minimum = minimum
        self.maximum = maximum
        self.pattern = pattern
        self.item_type = item_type
        self.evidence = evidence
        self.notes = notes

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "name": self.name,
            "type": self.param_type,
            "required": self.required,
            "description": self.description,
            "default": self.default,
            "evidence": self.evidence,
            "notes": self.notes
        }
        if self.enum is not None:
            d["enum"] = self.enum
        if self.minimum is not None:
            d["minimum"] = self.minimum
        if self.maximum is not None:
            d["maximum"] = self.maximum
        if self.pattern is not None:
            d["pattern"] = self.pattern
        if self.item_type is not None:
            d["item_type"] = self.item_type
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ParameterRequirement":
        return cls(
            name=data["name"],
            param_type=data.get("type", "any"),
            required=data.get("required", False),
            description=data.get("description"),
            default=data.get("default"),
            enum=data.get("enum"),
            minimum=data.get("minimum"),
            maximum=data.get("maximum"),
            pattern=data.get("pattern"),
            item_type=data.get("item_type"),
            evidence=data.get("evidence", EvidenceSource.EXTRACTED),
            notes=data.get("notes", "")
        )

    @classmethod
    def from_parameter_profile(cls, p: Union[ParameterProfile, Dict[str, Any]]) -> "ParameterRequirement":
        if isinstance(p, dict):
            return cls.from_dict(p)
        return cls(
            name=p.name,
            param_type=p.param_type,
            required=p.required,
            description=p.description,
            default=p.default,
            evidence=p.evidence,
            notes=p.notes
        )


class MappedParameter:
    """
    Evidence-grounded parameter value extracted from natural language or structured input.
    """
    def __init__(
        self,
        name: str,
        raw_value: Any,
        normalized_value: Any,
        source_text: str,
        mapping_method: str,
        is_explicit: bool,
        is_valid: bool = True,
        validation_error: Optional[str] = None,
        confidence: float = 1.0
    ):
        self.name = name
        self.raw_value = raw_value
        self.normalized_value = normalized_value
        self.source_text = source_text
        self.mapping_method = mapping_method
        self.is_explicit = is_explicit
        self.is_valid = is_valid
        self.validation_error = validation_error
        self.confidence = confidence

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "raw_value": self.raw_value,
            "normalized_value": self.normalized_value,
            "source_text": self.source_text,
            "mapping_method": self.mapping_method,
            "is_explicit": self.is_explicit,
            "is_valid": self.is_valid,
            "validation_error": self.validation_error,
            "confidence": self.confidence
        }


class ParameterReadinessResult:
    """
    Complete, inspectable result of Capability Parameter Understanding.
    """
    def __init__(
        self,
        status: str,
        capability_urn: str,
        mapped_parameters: Dict[str, MappedParameter],
        missing_required: List[str],
        missing_optional: List[str],
        unknown_inputs: Dict[str, Any],
        clarifying_questions: List[str],
        explanation: str,
        raw_input: str
    ):
        if status not in VALID_READINESS_STATUSES:
            raise ValueError(f"Invalid readiness status '{status}'. Must be one of {sorted(VALID_READINESS_STATUSES)}")
        self.status = status
        self.capability_urn = capability_urn
        self.mapped_parameters = dict(mapped_parameters)
        self.missing_required = list(missing_required)
        self.missing_optional = list(missing_optional)
        self.unknown_inputs = dict(unknown_inputs)
        self.clarifying_questions = list(clarifying_questions)
        self.explanation = explanation
        self.raw_input = raw_input

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "capability_urn": self.capability_urn,
            "mapped_parameters": {k: v.to_dict() for k, v in self.mapped_parameters.items()},
            "missing_required": self.missing_required,
            "missing_optional": self.missing_optional,
            "unknown_inputs": self.unknown_inputs,
            "clarifying_questions": self.clarifying_questions,
            "explanation": self.explanation,
            "raw_input": self.raw_input
        }


# ----------------------------------------------------------------------------
# Core Engine: ParameterUnderstandingEngineV1
# ----------------------------------------------------------------------------

class ParameterUnderstandingEngineV1:
    """
    Deterministic capability parameter understanding engine.
    Extracts requirements from semantic profiles, parses natural language inputs,
    performs type validation and constraint checks, and returns explainable readiness results.
    """

    def __init__(self, conn: Optional[Any] = None, profile_service: Optional[CapabilityProfileService] = None):
        self.conn = conn
        self.profile_service = profile_service

    # ------------------------------------------------------------------------
    # 1. Parameter Understanding: Schema & Profile Introspection
    # ------------------------------------------------------------------------

    def get_parameter_requirements(
        self,
        capability: Union[str, CapabilitySemanticProfile, Dict[str, Any]],
        raw_schema: Optional[Dict[str, Any]] = None
    ) -> Tuple[List[ParameterRequirement], str]:
        """
        Extracts structured ParameterRequirements from a capability profile or raw schema.
        Returns: (requirements_list, evidence_status)
        """
        # Case A: Capability URN string passed
        if isinstance(capability, str):
            urn = capability.strip()
            try:
                parse_canonical_urn(urn)
            except Exception:
                pass
            if self.profile_service:
                profile = self.profile_service.get_profile(urn)
                return self._extract_from_profile(profile, raw_schema)
            if raw_schema is not None:
                return self._extract_from_raw_schema(raw_schema), EvidenceSource.EXTRACTED
            raise ValueError("profile_service is required to resolve capability URN string when raw_schema is not provided.")

        # Case B: CapabilitySemanticProfile object passed
        if isinstance(capability, CapabilitySemanticProfile):
            return self._extract_from_profile(capability, raw_schema)

        # Case C: Dictionary passed (either raw JSON schema or serialized/partial profile)
        if isinstance(capability, dict):
            if "inputs" in capability and isinstance(capability.get("inputs"), dict):
                inputs_dict = capability["inputs"]
                ev = inputs_dict.get("evidence", EvidenceSource.EXTRACTED)
                val = inputs_dict.get("value")
                if ev == EvidenceSource.UNKNOWN or val is None:
                    if raw_schema and isinstance(raw_schema, dict) and raw_schema.get("properties"):
                        return self._extract_from_raw_schema(raw_schema), EvidenceSource.EXTRACTED
                    return [], EvidenceSource.UNKNOWN
                if val == []:
                    return [], EvidenceSource.EXTRACTED
                # If full profile dictionary
                if "capability_id" in capability and "display_name" in capability:
                    prof = CapabilitySemanticProfile.from_dict(capability)
                    return self._extract_from_profile(prof, raw_schema)
                # Partial profile dictionary with inputs value list
                reqs = [ParameterRequirement.from_parameter_profile(p) for p in val]
                return reqs, ev
            # Raw JSON schema (e.g. {"type": "object", "properties": {...}})
            return self._extract_from_raw_schema(capability), EvidenceSource.EXTRACTED

        raise TypeError(f"Unsupported capability representation: {type(capability)}")

    def _extract_from_profile(
        self,
        profile: CapabilitySemanticProfile,
        raw_schema: Optional[Dict[str, Any]] = None
    ) -> Tuple[List[ParameterRequirement], str]:
        """Extracts requirements from a CapabilitySemanticProfile and optional raw schema overlay."""
        evidence = profile.inputs.evidence

        if evidence == EvidenceSource.UNKNOWN or profile.inputs.value is None:
            # Check if raw_schema is provided as fallback overlay
            if raw_schema and isinstance(raw_schema, dict) and raw_schema.get("properties"):
                return self._extract_from_raw_schema(raw_schema), EvidenceSource.EXTRACTED
            return [], EvidenceSource.UNKNOWN

        # Schema explicitly specifies 0 parameters
        if profile.inputs.value == []:
            return [], EvidenceSource.EXTRACTED

        raw_props = raw_schema.get("properties", {}) if raw_schema else {}
        reqs: List[ParameterRequirement] = []

        for p_dict in profile.inputs.value:
            p_name = p_dict["name"]
            prop_def = raw_props.get(p_name, {}) if isinstance(raw_props, dict) else {}

            enum_vals = prop_def.get("enum")
            min_val = prop_def.get("minimum")
            max_val = prop_def.get("maximum")
            pattern = prop_def.get("pattern")
            item_type = None

            p_type = p_dict.get("type", "any")
            if p_type.startswith("array of "):
                item_type = p_type[len("array of "):]
            elif prop_def.get("items", {}).get("type"):
                item_type = prop_def["items"]["type"]

            req = ParameterRequirement(
                name=p_name,
                param_type=p_type,
                required=p_dict.get("required", False),
                description=p_dict.get("description"),
                default=p_dict.get("default"),
                enum=enum_vals,
                minimum=min_val,
                maximum=max_val,
                pattern=pattern,
                item_type=item_type,
                evidence=p_dict.get("evidence", EvidenceSource.EXTRACTED),
                notes=p_dict.get("notes", "")
            )
            reqs.append(req)

        return reqs, EvidenceSource.EXTRACTED

    def _extract_from_raw_schema(self, schema: Dict[str, Any]) -> List[ParameterRequirement]:
        """Extracts requirements directly from a standard JSON schema dictionary."""
        properties = schema.get("properties", {})
        required_set = set(schema.get("required", []))
        reqs: List[ParameterRequirement] = []

        for prop_name, prop_def in sorted(properties.items()):
            if not isinstance(prop_def, dict):
                prop_def = {}

            p_type = prop_def.get("type", "any")
            item_type = None
            if p_type == "array":
                item_type = prop_def.get("items", {}).get("type", "any")
                p_type = f"array of {item_type}"

            req = ParameterRequirement(
                name=prop_name,
                param_type=p_type,
                required=prop_name in required_set,
                description=prop_def.get("description") or prop_def.get("title"),
                default=prop_def.get("default"),
                enum=prop_def.get("enum"),
                minimum=prop_def.get("minimum"),
                maximum=prop_def.get("maximum"),
                pattern=prop_def.get("pattern"),
                item_type=item_type,
                evidence=EvidenceSource.EXTRACTED,
                notes="Extracted from raw schema."
            )
            reqs.append(req)

        return reqs

    # ------------------------------------------------------------------------
    # 2. Natural-Language Input Mapping
    # ------------------------------------------------------------------------

    def parse_user_input(
        self,
        user_input: Union[str, Dict[str, Any]],
        requirements: List[ParameterRequirement]
    ) -> Tuple[Dict[str, Tuple[Any, str, str, bool]], Dict[str, Any], Dict[str, str]]:
        """
        Parses explicit and natural-language user inputs into candidate parameter values.
        Returns:
          mapped: {param_name: (raw_val, source_text, mapping_method, is_explicit)}
          unknowns: {key: val}
          ambiguities: {param_name: explanation}
        """
        mapped: Dict[str, Tuple[Any, str, str, bool]] = {}
        unknowns: Dict[str, Any] = {}
        ambiguities: Dict[str, str] = {}
        known_names = {r.name for r in requirements}

        # Case 1: Structured Dictionary input passed
        if isinstance(user_input, dict):
            for k, v in user_input.items():
                if k in known_names:
                    mapped[k] = (v, f"{k}: {json.dumps(v) if not isinstance(v, str) else v}", MappingMethod.EXPLICIT_KEY_VALUE, True)
                else:
                    unknowns[k] = v
            return mapped, unknowns, ambiguities

        text = str(user_input or "").strip()
        if not text:
            return mapped, unknowns, ambiguities

        # Case 2: Embedded JSON string in text (e.g. '... {"repo_path": "/var/repo"} ...')
        json_matches = re.findall(r"\{[^{}]*\}", text)
        for jm in json_matches:
            try:
                parsed_json = json.loads(jm)
                if isinstance(parsed_json, dict):
                    for k, v in parsed_json.items():
                        if k in known_names:
                            if k in mapped and mapped[k][0] != v:
                                ambiguities[k] = f"Conflicting values provided for '{k}': {mapped[k][0]!r} vs {v!r}"
                            else:
                                mapped[k] = (v, jm, MappingMethod.EXPLICIT_JSON, True)
                        else:
                            unknowns[k] = v
            except Exception:
                pass

        # Case 3: Key-Value pairs: key=value, key="value", key='value', key: value
        kv_patterns = [
            # --key=value or --key "value" or --key value
            r"--(?P<key>[a-zA-Z0-9_-]+)(?:=(?P<val1>\"[^\"]*\"|'[^']*'|[^\s,]+)|\s+(?P<val2>\"[^\"]*\"|'[^']*'|[^\s,]+))",
            # key="value" or key='value' or key=value
            r"\b(?P<key>[a-zA-Z0-9_-]+)=(?P<val>\"[^\"]*\"|'[^']*'|\[[^\]]*\]|[^\s,]+)",
            # key: "value" or key: 'value' or key: value
            r"\b(?P<key>[a-zA-Z0-9_-]+)\s*:\s*(?P<val>\"[^\"]*\"|'[^']*'|\[[^\]]*\]|[^\s,]+)",
            # key is "value" or key is value
            r"\b(?P<key>[a-zA-Z0-9_-]+)\s+is\s+(?P<val>\"[^\"]*\"|'[^']*'|[^\s,]+)",
            # set key to "value"
            r"\bset\s+(?P<key>[a-zA-Z0-9_-]+)\s+to\s+(?P<val>\"[^\"]*\"|'[^']*'|[^\s,]+)"
        ]

        for pat in kv_patterns:
            for match in re.finditer(pat, text):
                groups = match.groupdict()
                raw_k = groups.get("key", "").strip()
                # Normalize key by replacing hyphens with underscores to match pythonic schema names
                norm_k = raw_k.replace("-", "_")
                raw_v = groups.get("val") or groups.get("val1") or groups.get("val2") or ""
                raw_v = raw_v.strip()

                # Strip bounding quotes
                if (raw_v.startswith('"') and raw_v.endswith('"')) or (raw_v.startswith("'") and raw_v.endswith("'")):
                    val = raw_v[1:-1]
                else:
                    val = raw_v

                matched_name = None
                if norm_k in known_names:
                    matched_name = norm_k
                elif raw_k in known_names:
                    matched_name = raw_k

                if matched_name:
                    if matched_name in mapped and mapped[matched_name][0] != val:
                        ambiguities[matched_name] = f"Conflicting values provided for '{matched_name}': {mapped[matched_name][0]!r} vs {val!r}"
                    elif matched_name not in mapped:
                        mapped[matched_name] = (val, match.group(0), MappingMethod.EXPLICIT_KEY_VALUE, True)
                else:
                    if raw_k not in unknowns and not raw_k.isdigit():
                        unknowns[raw_k] = val

        # Case 4: Contextual / Semantic Slot Extraction for Unmapped Requirements
        for req in requirements:
            if req.name in mapped or req.name in ambiguities:
                continue

            extracted, slot_ambiguity = self._extract_semantic_slot(text, req, mapped)
            if slot_ambiguity:
                ambiguities[req.name] = slot_ambiguity
            elif extracted is not None:
                val, source_substr, method = extracted
                mapped[req.name] = (val, source_substr, method, True)

        return mapped, unknowns, ambiguities

    def _extract_semantic_slot(
        self,
        text: str,
        req: ParameterRequirement,
        current_mapped: Dict[str, Any]
    ) -> Tuple[Optional[Tuple[Any, str, str]], Optional[str]]:
        """
        Deterministically extracts an argument for a parameter from natural language context.
        Returns: (extracted_tuple, ambiguity_error)
        """
        name = req.name.lower()
        ptype = req.param_type.lower()

        # 1. Filesystem Paths (repo_path, file_path, path, target_dir, dest_dir)
        if any(term in name for term in ("path", "dir", "directory", "folder", "file")):
            path_pattern = r"(?:(?:\"|')([a-zA-Z0-9_\-\./\\]+)(?:\"|')|((?:/[a-zA-Z0-9_\-\.]+)+|\./[a-zA-Z0-9_\-\./]+|~/[a-zA-Z0-9_\-\./]+|[a-zA-Z]:[/\\][a-zA-Z0-9_\-\./\\]+))"
            path_matches = []
            for m in re.finditer(path_pattern, text):
                candidate = m.group(1) or m.group(2)
                if not candidate:
                    continue
                # Require genuine path characteristics: must have '/' or '\' or start with '.' or '~'
                # to prevent plain words like 'main' or 'hello' inside quotes from being treated as paths
                is_path_like = (
                    "/" in candidate or
                    "\\" in candidate or
                    candidate.startswith(".") or
                    candidate.startswith("~") or
                    (len(candidate) >= 2 and candidate[1] == ":")
                )
                if is_path_like and not any(candidate == v[0] for v in current_mapped.values()):
                    if candidate not in [p[0] for p in path_matches]:
                        path_matches.append((candidate, m.group(0), MappingMethod.PATTERN_EXTRACTION))
            if len(path_matches) == 1:
                return path_matches[0], None
            elif len(path_matches) > 1:
                return None, f"Ambiguous input: multiple filesystem paths match parameter '{req.name}': {[p[0] for p in path_matches]}"

        # 2. URLs (repo_url, url, uri)
        if any(term in name for term in ("url", "uri")):
            url_pattern = r"(https?://[^\s\"']+|git@[^\s\"']+)"
            url_matches = []
            for m in re.finditer(url_pattern, text):
                u = m.group(1)
                if u not in [x[0] for x in url_matches]:
                    url_matches.append((u, m.group(0), MappingMethod.PATTERN_EXTRACTION))
            if len(url_matches) == 1:
                return url_matches[0], None
            elif len(url_matches) > 1:
                return None, f"Ambiguous input: multiple URLs match parameter '{req.name}': {[u[0] for u in url_matches]}"

        # 3. Commit / Hash / Revision (commit_hash, revision, hash)
        if any(term in name for term in ("commit", "revision", "hash")):
            # Look for 40-char SHA-1 or 7-8 char abbreviated hash
            hash_pattern = r"\b([0-9a-fA-F]{40}|[0-9a-fA-F]{7,8})\b"
            hash_matches = []
            for m in re.finditer(hash_pattern, text):
                candidate = m.group(1)
                if not any(candidate == v[0] for v in current_mapped.values()):
                    if candidate not in [h[0] for h in hash_matches]:
                        hash_matches.append((candidate, m.group(0), MappingMethod.PATTERN_EXTRACTION))
            if len(hash_matches) == 1:
                return hash_matches[0], None
            elif len(hash_matches) > 1:
                return None, f"Ambiguous input: multiple commit/hash candidates match parameter '{req.name}': {[h[0] for h in hash_matches]}"

        # 4. JSON Array extraction for array parameters (e.g. samples, numbers, list)
        if "array" in ptype or "list" in ptype or any(term in name for term in ("samples", "numbers", "list", "array", "values", "items")):
            arr_pattern = r"(\[\s*(?:-?\d+(?:\.\d+)?(?:\s*,\s*-?\d+(?:\.\d+)?)*)?\s*\])"
            arr_matches = []
            for m in re.finditer(arr_pattern, text):
                try:
                    parsed_arr = json.loads(m.group(1))
                    if isinstance(parsed_arr, list):
                        if parsed_arr not in [a[0] for a in arr_matches]:
                            arr_matches.append((parsed_arr, m.group(0), MappingMethod.PATTERN_EXTRACTION))
                except Exception:
                    pass
            if len(arr_matches) == 1:
                return arr_matches[0], None
            elif len(arr_matches) > 1:
                return None, f"Ambiguous input: multiple array structures match parameter '{req.name}': {[a[0] for a in arr_matches]}"

        # 5. Enum matching (e.g. algorithm, format, dialect, compression)
        if req.enum:
            enum_matches = []
            for enum_opt in req.enum:
                enum_pat = r"\b" + re.escape(str(enum_opt)) + r"\b"
                m = re.search(enum_pat, text, re.IGNORECASE)
                if m:
                    if enum_opt not in [e[0] for e in enum_matches]:
                        enum_matches.append((enum_opt, m.group(0), MappingMethod.PATTERN_EXTRACTION))
            if len(enum_matches) == 1:
                return enum_matches[0], None
            elif len(enum_matches) > 1:
                return None, f"Ambiguous input: multiple enum values match parameter '{req.name}': {[e[0] for e in enum_matches]}"

        # 6. Boolean flag presence or phrasing (e.g. "include remote", "allow prerelease")
        if ptype == "boolean":
            clean_name_phrase = name.replace("_", " ")
            has_enable = re.search(r"\b(with|enable|allow|include)\s+" + re.escape(clean_name_phrase) + r"\b", text, re.IGNORECASE)
            has_disable = re.search(r"\b(without|no|disable|exclude)\s+" + re.escape(clean_name_phrase) + r"\b", text, re.IGNORECASE)
            if has_enable and has_disable:
                return None, f"Ambiguous input: conflicting boolean flags for '{req.name}'"
            if has_enable:
                return (True, clean_name_phrase, MappingMethod.SEMANTIC_MATCH), None
            if has_disable:
                return (False, clean_name_phrase, MappingMethod.SEMANTIC_MATCH), None

        # 7. Quoted string match for specific string parameters
        if ptype == "string":
            quoted_pat = r"\b" + re.escape(name.replace("_", " ")) + r"[:\s]+(?:\"([^\"]+)\"|'([^']+)')"
            m = re.search(quoted_pat, text, re.IGNORECASE)
            if m:
                val = m.group(1) or m.group(2)
                return (val, m.group(0), MappingMethod.SEMANTIC_MATCH), None

        # 8. Numeric slot match (e.g. depth <int>, ddof <int>)
        if ptype in ("integer", "number"):
            num_pat = r"\b" + re.escape(name.replace("_", " ")) + r"[:\s]+(-?\d+(?:\.\d+)?)\b"
            m = re.search(num_pat, text, re.IGNORECASE)
            if m:
                return (m.group(1), m.group(0), MappingMethod.SEMANTIC_MATCH), None

        return None, None

        return None

    # ------------------------------------------------------------------------
    # 3. Validation & Type Enforcement
    # ------------------------------------------------------------------------

    def validate_and_normalize(
        self,
        req: ParameterRequirement,
        raw_val: Any
    ) -> Tuple[bool, Any, Optional[str]]:
        """
        Validates raw_val against req's type and constraints without silent coercion.
        Returns: (is_valid, normalized_val, error_message)
        """
        ptype = (req.param_type or "any").lower()

        # 1. Null / None validation
        if raw_val is None:
            if req.required and req.default is None:
                return False, None, f"Required parameter '{req.name}' cannot be null."
            return True, req.default, None

        # 2. String Type
        if ptype == "string":
            if not isinstance(raw_val, str):
                return False, raw_val, f"Parameter '{req.name}' expects string, got {type(raw_val).__name__}."
            norm_val = raw_val.strip()

            # Enum constraint
            if req.enum is not None:
                # Case-matching or canonical matching
                match = next((e for e in req.enum if str(e).lower() == norm_val.lower()), None)
                if match is None:
                    return False, norm_val, (
                        f"Value '{norm_val}' is not allowed for '{req.name}'. "
                        f"Allowed values: {req.enum}."
                    )
                norm_val = match

            # Regex pattern constraint
            if req.pattern is not None:
                if not re.search(req.pattern, norm_val):
                    return False, norm_val, f"Value '{norm_val}' does not match pattern '{req.pattern}'."

            return True, norm_val, None

        # 3. Integer Type
        if ptype == "integer":
            norm_int: Optional[int] = None
            if isinstance(raw_val, bool):
                return False, raw_val, f"Parameter '{req.name}' expects integer, got boolean ({raw_val})."
            elif isinstance(raw_val, int):
                norm_int = raw_val
            elif isinstance(raw_val, float):
                if raw_val.is_integer():
                    norm_int = int(raw_val)
                else:
                    return False, raw_val, f"Parameter '{req.name}' expects integer, got fractional float {raw_val}."
            elif isinstance(raw_val, str):
                raw_str = raw_val.strip()
                if re.fullmatch(r"[-+]?\d+", raw_str):
                    norm_int = int(raw_str)
                else:
                    return False, raw_val, f"Parameter '{req.name}' cannot parse '{raw_val}' as integer."
            else:
                return False, raw_val, f"Parameter '{req.name}' expects integer, got {type(raw_val).__name__}."

            # Numeric bounds check
            if req.minimum is not None and norm_int < req.minimum:
                return False, norm_int, f"Value {norm_int} violates minimum bound ({req.minimum}) for '{req.name}'."
            if req.maximum is not None and norm_int > req.maximum:
                return False, norm_int, f"Value {norm_int} violates maximum bound ({req.maximum}) for '{req.name}'."

            # Enum check
            if req.enum is not None and norm_int not in req.enum:
                return False, norm_int, f"Value {norm_int} is not in allowed enum {req.enum} for '{req.name}'."

            return True, norm_int, None

        # 4. Number / Float Type
        if ptype in ("number", "float"):
            norm_num: Optional[float] = None
            if isinstance(raw_val, bool):
                return False, raw_val, f"Parameter '{req.name}' expects number, got boolean ({raw_val})."
            elif isinstance(raw_val, (int, float)):
                norm_num = float(raw_val)
            elif isinstance(raw_val, str):
                try:
                    norm_num = float(raw_val.strip())
                except ValueError:
                    return False, raw_val, f"Parameter '{req.name}' cannot parse '{raw_val}' as number."
            else:
                return False, raw_val, f"Parameter '{req.name}' expects number, got {type(raw_val).__name__}."

            if req.minimum is not None and norm_num < req.minimum:
                return False, norm_num, f"Value {norm_num} violates minimum bound ({req.minimum}) for '{req.name}'."
            if req.maximum is not None and norm_num > req.maximum:
                return False, norm_num, f"Value {norm_num} violates maximum bound ({req.maximum}) for '{req.name}'."

            return True, norm_num, None

        # 5. Boolean Type
        if ptype == "boolean":
            if isinstance(raw_val, bool):
                return True, raw_val, None
            if isinstance(raw_val, str):
                s = raw_val.strip().lower()
                if s in ("true", "yes", "1", "t", "y"):
                    return True, True, None
                if s in ("false", "no", "0", "f", "n"):
                    return True, False, None
                return False, raw_val, f"Parameter '{req.name}' cannot parse boolean from '{raw_val}'."
            if isinstance(raw_val, int):
                if raw_val == 1:
                    return True, True, None
                if raw_val == 0:
                    return True, False, None
            return False, raw_val, f"Parameter '{req.name}' expects boolean, got {type(raw_val).__name__}."

        # 6. Array Type
        if ptype.startswith("array") or ptype.startswith("list"):
            norm_arr: Optional[List[Any]] = None
            if isinstance(raw_val, (list, tuple)):
                norm_arr = list(raw_val)
            elif isinstance(raw_val, str):
                raw_str = raw_val.strip()
                if raw_str.startswith("[") and raw_str.endswith("]"):
                    try:
                        parsed = json.loads(raw_str)
                        if isinstance(parsed, list):
                            norm_arr = parsed
                    except Exception:
                        pass
                if norm_arr is None and "," in raw_str:
                    norm_arr = [elem.strip() for elem in raw_str.split(",")]
                elif norm_arr is None:
                    # Single item array or invalid
                    try:
                        parsed = json.loads(f"[{raw_str}]")
                        if isinstance(parsed, list):
                            norm_arr = parsed
                    except Exception:
                        norm_arr = [raw_str]
            else:
                return False, raw_val, f"Parameter '{req.name}' expects array, got {type(raw_val).__name__}."

            # Element type validation if item_type is known
            item_t = req.item_type
            if item_t and norm_arr:
                validated_elements = []
                for idx, elem in enumerate(norm_arr):
                    dummy_req = ParameterRequirement(name=f"{req.name}[{idx}]", param_type=item_t, required=True)
                    el_valid, el_norm, el_err = self.validate_and_normalize(dummy_req, elem)
                    if not el_valid:
                        return False, raw_val, f"Array item error in '{req.name}[{idx}]': {el_err}"
                    validated_elements.append(el_norm)
                norm_arr = validated_elements

            return True, norm_arr, None

        # 7. Object / Dict Type
        if ptype in ("object", "dict"):
            if isinstance(raw_val, dict):
                return True, raw_val, None
            if isinstance(raw_val, str):
                try:
                    parsed = json.loads(raw_val.strip())
                    if isinstance(parsed, dict):
                        return True, parsed, None
                    return False, raw_val, f"Parameter '{req.name}' expected JSON object, got {type(parsed).__name__}."
                except Exception as e:
                    return False, raw_val, f"Parameter '{req.name}' failed to parse JSON object: {e}"
            return False, raw_val, f"Parameter '{req.name}' expects object, got {type(raw_val).__name__}."

        # 8. Any / Untyped
        return True, raw_val, None

    # ------------------------------------------------------------------------
    # 4. Readiness Evaluation & Question Generation
    # ------------------------------------------------------------------------

    def evaluate_readiness(
        self,
        capability: Union[str, CapabilitySemanticProfile, Dict[str, Any]],
        user_input: Union[str, Dict[str, Any]],
        raw_schema: Optional[Dict[str, Any]] = None,
        strict_unknowns: bool = False
    ) -> ParameterReadinessResult:
        """
        Executes complete parameter understanding, mapping, validation, and readiness evaluation.
        """
        # Step 1: Introspect capability requirements
        cap_urn = "(unspecified)"
        if isinstance(capability, str):
            cap_urn = capability
        elif isinstance(capability, CapabilitySemanticProfile):
            cap_urn = capability.capability_id
        elif isinstance(capability, dict):
            cap_urn = capability.get("capability_id", capability.get("name", "custom-schema"))

        raw_input_str = json.dumps(user_input) if isinstance(user_input, dict) else str(user_input or "")

        requirements, evidence = self.get_parameter_requirements(capability, raw_schema)

        # Check Schema Boundaries (INCOMPATIBLE checks)
        # 1. Unknown input schema
        if evidence == EvidenceSource.UNKNOWN:
            return ParameterReadinessResult(
                status=ParameterReadinessStatus.INCOMPATIBLE,
                capability_urn=cap_urn,
                mapped_parameters={},
                missing_required=[],
                missing_optional=[],
                unknown_inputs={},
                clarifying_questions=[],
                explanation=(
                    f"Capability '{cap_urn}' has undeclared or unknown input schema parameters. "
                    "Cannot safely map or validate input arguments against an unknown interface."
                ),
                raw_input=raw_input_str
            )

        # Step 2: Parse user input
        parsed_candidates, unknown_inputs, ambiguities = self.parse_user_input(user_input, requirements)

        # 2. Capability specifies zero parameters but parameters were supplied
        if len(requirements) == 0:
            if parsed_candidates or unknown_inputs or ambiguities:
                supplied_names = list(parsed_candidates.keys()) + list(unknown_inputs.keys()) + list(ambiguities.keys())
                return ParameterReadinessResult(
                    status=ParameterReadinessStatus.INCOMPATIBLE,
                    capability_urn=cap_urn,
                    mapped_parameters={},
                    missing_required=[],
                    missing_optional=[],
                    unknown_inputs=unknown_inputs,
                    clarifying_questions=[],
                    explanation=(
                        f"Capability '{cap_urn}' explicitly takes zero input parameters, "
                        f"but input arguments were supplied: {sorted(supplied_names)}."
                    ),
                    raw_input=raw_input_str
                )
            return ParameterReadinessResult(
                status=ParameterReadinessStatus.READY,
                capability_urn=cap_urn,
                mapped_parameters={},
                missing_required=[],
                missing_optional=[],
                unknown_inputs={},
                clarifying_questions=[],
                explanation=f"Capability '{cap_urn}' takes zero input parameters. Ready for invocation.",
                raw_input=raw_input_str
            )

        # Step 3: Validate and normalize mapped parameters
        mapped_results: Dict[str, MappedParameter] = {}
        missing_required: List[str] = []
        missing_optional: List[str] = []
        has_invalid = False
        invalid_reasons: List[str] = []

        req_map = {r.name: r for r in requirements}

        # Check ambiguities
        for ambig_param, ambig_err in ambiguities.items():
            has_invalid = True
            invalid_reasons.append(ambig_err)
            mapped_results[ambig_param] = MappedParameter(
                name=ambig_param,
                raw_value=None,
                normalized_value=None,
                source_text="Ambiguous input",
                mapping_method=MappingMethod.SEMANTIC_MATCH,
                is_explicit=True,
                is_valid=False,
                validation_error=ambig_err
            )

        # Check strict unknowns
        if strict_unknowns and unknown_inputs:
            has_invalid = True
            invalid_reasons.append(f"Unknown input parameters not allowed by schema: {sorted(unknown_inputs.keys())}")

        for req in requirements:
            if req.name in mapped_results and not mapped_results[req.name].is_valid:
                # Already recorded as ambiguity error
                continue

            if req.name in parsed_candidates:
                raw_val, src_text, method, is_explicit = parsed_candidates[req.name]
                is_valid, norm_val, err_msg = self.validate_and_normalize(req, raw_val)

                mapped_param = MappedParameter(
                    name=req.name,
                    raw_value=raw_val,
                    normalized_value=norm_val,
                    source_text=src_text,
                    mapping_method=method,
                    is_explicit=is_explicit,
                    is_valid=is_valid,
                    validation_error=err_msg
                )
                mapped_results[req.name] = mapped_param

                if not is_valid:
                    has_invalid = True
                    invalid_reasons.append(err_msg or f"Invalid value for '{req.name}'.")
            else:
                # Parameter not supplied in user input
                if req.default is not None:
                    # Valid schema default satisfies the parameter's requirement
                    is_valid, norm_val, err_msg = self.validate_and_normalize(req, req.default)
                    mapped_results[req.name] = MappedParameter(
                        name=req.name,
                        raw_value=req.default,
                        normalized_value=norm_val,
                        source_text=f"Schema default for '{req.name}'",
                        mapping_method=MappingMethod.DEFAULT_VALUE,
                        is_explicit=False,
                        is_valid=is_valid,
                        validation_error=err_msg
                    )
                    if not is_valid:
                        has_invalid = True
                        invalid_reasons.append(err_msg or f"Invalid default value for '{req.name}'.")
                else:
                    # Parameter has no default value
                    if req.required:
                        missing_required.append(req.name)
                    else:
                        missing_optional.append(req.name)

        # Step 4: Generate Clarifying Questions for Missing Required Info
        clarifying_questions: List[str] = []
        for req_name in sorted(missing_required):
            req_def = req_map[req_name]
            q = f"Please provide required parameter '{req_name}'"
            details = []
            if req_def.description:
                details.append(req_def.description)
            details.append(f"type: {req_def.param_type}")
            if req_def.enum:
                details.append(f"allowed values: {', '.join(map(str, req_def.enum))}")
            if details:
                q += f" ({'; '.join(details)})."
            else:
                q += "."
            clarifying_questions.append(q)

        # Step 5: Compute Final Readiness Status and Explanation
        if has_invalid:
            status = ParameterReadinessStatus.INVALID
            explanation = "Supplied parameter values violate capability schema constraints: " + "; ".join(invalid_reasons)
        elif missing_required:
            status = ParameterReadinessStatus.INCOMPLETE
            explanation = (
                f"Missing {len(missing_required)} required parameter(s): {sorted(missing_required)}. "
                "Clarifying questions have been generated."
            )
        else:
            status = ParameterReadinessStatus.READY
            notes = []
            default_count = sum(1 for p in mapped_results.values() if p.mapping_method == MappingMethod.DEFAULT_VALUE)
            if default_count > 0:
                notes.append(f"{default_count} parameter(s) satisfied by schema default")
            if missing_optional:
                notes.append(f"{len(missing_optional)} optional parameter(s) omitted without default")
            if unknown_inputs:
                notes.append(f"ignoring {len(unknown_inputs)} unrecognized input(s): {sorted(unknown_inputs.keys())}")

            note_str = f" ({'; '.join(notes)})" if notes else ""
            explanation = f"All required parameters satisfied and valid{note_str}. Ready."

        return ParameterReadinessResult(
            status=status,
            capability_urn=cap_urn,
            mapped_parameters=mapped_results,
            missing_required=missing_required,
            missing_optional=missing_optional,
            unknown_inputs=unknown_inputs,
            clarifying_questions=clarifying_questions,
            explanation=explanation,
            raw_input=raw_input_str
        )

    # ------------------------------------------------------------------------
    # 5. CLI Formatting
    # ------------------------------------------------------------------------

    @staticmethod
    def format_cli_output(result: ParameterReadinessResult) -> str:
        """Formats the parameter readiness result for terminal presentation."""
        lines = []
        lines.append("=" * 74)
        lines.append(" LIVING CAPABILITY SYSTEM (LCS) — CAPABILITY PARAMETER UNDERSTANDING")
        lines.append("=" * 74)
        lines.append(f"  Target Capability:   {result.capability_urn}")
        lines.append(f"  Readiness Status:    {result.status}")
        lines.append(f"  Explanation:         {result.explanation}")

        lines.append("\n[Mapped Parameters]")
        if result.mapped_parameters:
            for name, mp in sorted(result.mapped_parameters.items()):
                tag = "EXPLICIT" if mp.is_explicit else "DEFAULT"
                val_status = "VALID" if mp.is_valid else "INVALID"
                lines.append(f"  * {name}: {json.dumps(mp.normalized_value)} [{val_status} | {tag} | {mp.mapping_method}]")
                lines.append(f"    - Source Text:     {mp.source_text!r}")
                if not mp.is_valid and mp.validation_error:
                    lines.append(f"    - Error:           {mp.validation_error}")
        else:
            lines.append("  * (No parameters mapped)")

        if result.missing_required:
            lines.append("\n[Missing Required Parameters]")
            for req in sorted(result.missing_required):
                lines.append(f"  ! {req} (REQUIRED)")

        if result.missing_optional:
            lines.append("\n[Missing Optional Parameters]")
            for opt in sorted(result.missing_optional):
                lines.append(f"  - {opt} (optional)")

        if result.unknown_inputs:
            lines.append("\n[Unknown / Unrecognized Inputs]")
            for k, v in sorted(result.unknown_inputs.items()):
                lines.append(f"  ? {k}: {json.dumps(v) if not isinstance(v, str) else v}")

        if result.clarifying_questions:
            lines.append("\n[Clarifying Questions]")
            for idx, q in enumerate(result.clarifying_questions, start=1):
                lines.append(f"  {idx}. {q}")

        lines.append("=" * 74)
        return "\n".join(lines)


__all__ = [
    "ParameterReadinessStatus",
    "VALID_READINESS_STATUSES",
    "MappingMethod",
    "ParameterRequirement",
    "MappedParameter",
    "ParameterReadinessResult",
    "ParameterUnderstandingEngineV1"
]

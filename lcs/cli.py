"""
Living Capability System (LCS) — Canonical CLI Tool
===================================================
Provides operator commands for:
  - lcs status
  - lcs discover
  - lcs search <query>
  - lcs inspect <urn>
  - lcs explain <urn>
"""

import os
import sys
import json
import argparse
import getpass
import shlex
from typing import List, Optional

# Ensure project root is importable
_PARENT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from lcs.config import LCSConfig
from lcs.context import LCSContext
from lcs.setup import SetupEngine, HostDetector, SetupDiagnostics
from lcs.policy import InterfaceTrustPolicy
from lcs import __version__
from lcs.registry import CanonicalCapabilityURN, parse_canonical_urn, InvalidCapabilityURNError, CapabilityNotFoundError
from lcs.governance import ApproverConsent, ApproverRole, GovernanceStatus, GovernanceError
from lcs.skills import ArtifactTaxonomyKind, EnvironmentOrigin, PrecedenceTier, SkillLifecycleState


def _format_table(rows: List[List[str]], headers: List[str]) -> str:
    """Formats ASCII table with column padding."""
    if not rows:
        return "(no results)"
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, val in enumerate(row):
            if i < len(col_widths):
                col_widths[i] = max(col_widths[i], len(str(val)))
            else:
                col_widths.append(len(str(val)))

    header_str = " | ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers))
    sep_str = "-+-".join("-" * col_widths[i] for i in range(len(headers)))
    row_strs = [
        " | ".join(str(r[i]).ljust(col_widths[i]) if i < len(r) else "".ljust(col_widths[i]) for i in range(len(headers)))
        for r in rows
    ]
    return f"{header_str}\n{sep_str}\n" + "\n".join(row_strs)


def cmd_status(ctx: LCSContext, args: argparse.Namespace) -> int:
    """Reports status of all LCS subsystems."""
    print("=" * 72)
    print(" LIVING CAPABILITY SYSTEM (LCS) — SYSTEM STATUS")
    print("=" * 72)

    # 1. Paths & Configuration
    print("\n[Configuration]")
    print(f"  LCS Root:          {ctx.config.root_dir}")
    print(f"  Database Path:     {ctx.config.db_path}")
    print(f"  CAS Root:          {ctx.config.cas_root}")
    print(f"  Key Store Dir:     {ctx.config.key_store_dir}")
    print(f"  Schema Dir:        {ctx.config.schema_dir}")

    # 2. Database & Migrations
    print("\n[Relational Database]")
    db_size = os.path.getsize(ctx.config.db_path) if os.path.exists(ctx.config.db_path) else 0
    print(f"  Database Size:     {db_size:,} bytes")
    try:
        cur = ctx.conn.cursor()
        cur.execute("PRAGMA journal_mode;")
        j_mode = cur.fetchone()[0]
        cur.execute("PRAGMA foreign_keys;")
        fk_val = cur.fetchone()[0]
        print(f"  Journal Mode:      {j_mode}")
        print(f"  Foreign Keys:      {'ENABLED (1)' if fk_val == 1 else 'DISABLED (0)'}")

        migrations = ctx.migration_manager.get_status()
        applied_count = sum(1 for m in migrations if m["applied"])
        print(f"  Migrations:        {applied_count}/{len(migrations)} applied")
        for m in migrations:
            st = "APPLIED" if m["applied"] else "PENDING"
            print(f"    - [{st}] {m['migration_id']} ({m['filename']})")
    except Exception as e:
        print(f"  Database Query Error: {e}")

    # 3. Content-Addressable Storage (CAS)
    print("\n[Content-Addressable Storage (CAS)]")
    objects_dir = os.path.join(ctx.config.cas_root, "objects")
    obj_count = 0
    total_obj_bytes = 0
    if os.path.exists(objects_dir):
        for root_p, _, files in os.walk(objects_dir):
            for fn in files:
                obj_count += 1
                try:
                    total_obj_bytes += os.path.getsize(os.path.join(root_p, fn))
                except OSError:
                    pass
    print(f"  Objects Count:     {obj_count} stored blobs")
    print(f"  Objects Volume:    {total_obj_bytes:,} bytes")
    print(f"  Staging Dir:       {os.path.join(ctx.config.cas_root, 'staging')}")
    print(f"  Leases Dir:        {os.path.join(ctx.config.cas_root, 'leases')}")
    print(f"  Receipts Dir:      {os.path.join(ctx.config.cas_root, 'receipts')}")

    # 4. Key Store
    print("\n[Cryptographic Key Store]")
    key_file = os.path.join(ctx.config.key_store_dir, "receipt_signing_key.bin")
    key_exists = os.path.exists(key_file)
    print(f"  Receipt Key:       {'PRESENT' if key_exists else 'NOT INITIALIZED'}")
    if key_exists:
        print(f"  Key File Size:     {os.path.getsize(key_file)} bytes")

    # 5. Registry Statistics
    print("\n[Capability Registry]")
    try:
        cur.execute("SELECT count(*) FROM capabilities;")
        cap_count = cur.fetchone()[0]
        cur.execute("SELECT lifecycle_state, count(*) FROM entity_urn_registry GROUP BY lifecycle_state;")
        state_counts = dict(cur.fetchall())
        print(f"  Registered Capabilities: {cap_count}")
        for state, cnt in sorted(state_counts.items()):
            print(f"    - {state}: {cnt}")
    except Exception as e:
        print(f"  Registry Query Error: {e}")

    # 6. Interface & Policy Statistics
    print("\n[Interface & Policy Engine]")
    try:
        cur.execute("SELECT count(*) FROM interface_declarations;")
        iface_count = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM interface_attestations;")
        attest_count = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM interface_policy_decisions;")
        dec_count = cur.fetchone()[0]
        print(f"  Registered Interfaces:   {iface_count}")
        print(f"  Interface Attestations:  {attest_count}")
        print(f"  Policy Decisions Log:    {dec_count}")
    except Exception as e:
        print(f"  Policy Query Error: {e}")

    # 7. Discovery FTS5 Index
    print("\n[FTS5 Discovery Index]")
    try:
        cur.execute("SELECT count(*) FROM capability_fts;")
        fts_count = cur.fetchone()[0]
        print(f"  Indexed Capabilities:    {fts_count}")
    except Exception as e:
        print(f"  Discovery Query Error: {e}")

    print("\n" + "=" * 72)
    return 0


def cmd_discover(ctx: LCSContext, args: argparse.Namespace) -> int:
    """Discovers tools from an MCP server and ingests them into LCS."""
    print("=" * 72)
    print(" LIVING CAPABILITY SYSTEM (LCS) — MCP CAPABILITY DISCOVERY")
    print("=" * 72)

    # Resolve server command
    if args.server_command:
        server_cmd = shlex.split(args.server_command)
    else:
        # Default to local MCP test fixture in project directory
        default_fixture = os.path.join(_PARENT, "mcp_test_server_fixture.py")
        if not os.path.exists(default_fixture):
            default_fixture = os.path.join(ctx.config.schema_dir, "mcp_test_server_fixture.py")
        server_cmd = [sys.executable, default_fixture]

    server_name = args.server_name or "local-document-tools"
    print(f"\nTarget MCP Server: {server_name}")
    print(f"Command:           {' '.join(server_cmd)}")

    trust_policy = InterfaceTrustPolicy(
        policy_name=args.policy_name or "mcp-discovered-tools-policy",
        allowed_attester_ids={"urn:lcs:attester:security:local-authority"},
        min_interface_version=1,
        require_attestation=True,
        require_all_capabilities_verified=True
    )

    timeout = float(args.timeout) if getattr(args, "timeout", None) is not None else 10.0
    custom_env = {}
    if getattr(args, "env", None):
        for item in args.env:
            if "=" in item:
                k, v = item.split("=", 1)
                custom_env[k.strip()] = v.strip()
            elif item.strip() in os.environ:
                custom_env[item.strip()] = os.environ[item.strip()]
    env_allowlist = set(args.allow_env) if getattr(args, "allow_env", None) else None

    try:
        summary = ctx.discovery_pipeline.discover_and_register_mcp_server(
            command=server_cmd,
            server_name=server_name,
            trust_policy=trust_policy,
            timeout=timeout,
            env_allowlist=env_allowlist,
            custom_env=custom_env
        )

        print("\n[Discovery Complete]")
        print(f"  Discovered Tools:        {len(summary.discovered_tools)}")
        print(f"  Associated Interface:    {summary.interface_urn}")
        print(f"  Attestation ID:          {summary.attestation_id}")
        print(f"  Policy Decision:         {summary.policy_decision.decision} ({summary.policy_decision.status})")

        print("\n[Discovered Capabilities]")
        table_rows = []
        for t in summary.discovered_tools:
            table_rows.append([t.raw_name, t.canonical_urn, t.category, t.source_server_name])
        print(_format_table(table_rows, ["Raw Name", "Canonical URN", "Category", "Source Server"]))

        print("\n[Policy Verification Audit]")
        for reason in summary.policy_decision.reasons:
            print(f"  * {reason}")

        print("\n" + "=" * 72)
        return 0
    except Exception as e:
        print(f"\nDiscovery Failed: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


def cmd_search(ctx: LCSContext, args: argparse.Namespace) -> int:
    """Searches registered capabilities via FTS5 full-text index."""
    query = args.query.strip()
    if not query:
        print("Error: Search query cannot be empty.", file=sys.stderr)
        return 1

    results = ctx.index_service.search(
        query=query,
        limit=args.limit,
        policy_filter=args.status
    )

    print(f"\nQuery: \"{query}\" (Matches: {len(results)})")
    if not results:
        print("No matching capabilities found.")
        return 0

    table_rows = []
    for r in results:
        table_rows.append([
            f"{r.rank:.2f}",
            r.name,
            r.trust_status,
            r.category,
            r.capability_urn
        ])

    print("\n" + _format_table(table_rows, ["Rank", "Name", "Status", "Category", "Canonical URN"]))

    print("\nDetails:")
    for i, r in enumerate(results, start=1):
        print(f"\n[{i}] {r.name} ({r.capability_urn})")
        print(f"    Description: {r.description}")
        print(f"    Status:      {r.trust_status}")
        print(f"    Origin:      {r.provenance_origin}")
        print(f"    Rank Score:  {r.rank:.4f}")

    return 0


def cmd_inspect(ctx: LCSContext, args: argparse.Namespace) -> int:
    """Inspects a capability's complete metadata and CAS stored definition."""
    urn = args.urn.strip()

    try:
        parsed_urn = parse_canonical_urn(urn)
    except InvalidCapabilityURNError as e:
        print(f"Error: Invalid capability URN: {e}", file=sys.stderr)
        return 1

    try:
        retrieved = ctx.cap_service.retrieve_capability(urn)
    except Exception as e:
        print(f"Error: Failed to retrieve capability '{urn}': {e}", file=sys.stderr)
        return 1

    cur = ctx.conn.cursor()
    cur.execute("SELECT lifecycle_state FROM entity_urn_registry WHERE entity_urn = ?;", (urn,))
    reg_row = cur.fetchone()
    lifecycle = reg_row[0] if reg_row else "UNKNOWN"

    defn = retrieved.definition

    print("=" * 72)
    print(f" LCS CAPABILITY INSPECTION: {defn.display_name}")
    print("=" * 72)
    print(f"  Canonical URN:      {defn.capability_id}")
    print(f"  Entity Kind:        {parsed_urn.entity_kind}")
    print(f"  Namespace:          {parsed_urn.namespace}")
    print(f"  Identifier:         {parsed_urn.identifier}")
    print(f"  Capability Type:    {defn.capability_type}")
    print(f"  Schema Version:     {defn.schema_version}")
    print(f"  Lifecycle State:    {lifecycle}")
    print(f"  Registered At:      {retrieved.registered_at}")
    print(f"  Definition Digest:  {retrieved.blob_digest}")
    print(f"  Byte Size:          {retrieved.stored_byte_length} bytes")
    print(f"  Input Interface:    {defn.input_interface_ref or '(none)'}")
    print(f"  Output Interface:   {defn.output_interface_ref or '(none)'}")
    print(f"  Description:        {defn.description}")

    # Associated Interface & Attestations
    cur.execute("""
        SELECT b.interface_urn, i.interface_version, i.agent_urn, e.lifecycle_state
        FROM interface_capability_bindings b
        JOIN interface_declarations i ON b.interface_urn = i.interface_urn
        LEFT JOIN entity_urn_registry e ON i.interface_urn = e.entity_urn
        WHERE b.capability_urn = ?;
    """, (urn,))
    bindings = cur.fetchall()

    print(f"\n[Bound Interfaces ({len(bindings)})]")
    for b in bindings:
        print(f"  - Interface URN:   {b[0]} (v{b[1]})")
        print(f"    Owning Agent:    {b[2]}")
        print(f"    Interface State: {b[3]}")

        # Fetch attestations for interface
        cur.execute("""
            SELECT attestation_id, attester_id, key_id, attested_at, attestation_blob_digest
            FROM interface_attestations
            WHERE interface_urn = ?
            ORDER BY attested_at DESC;
        """, (b[0],))
        attests = cur.fetchall()
        for a in attests:
            print(f"    * Attestation ID: {a[0]}")
            print(f"      Attester:       {a[1]}")
            print(f"      Key ID:         {a[2]}")
            print(f"      Attested At:    {a[3]}")
            print(f"      CAS Digest:     {a[4]}")

    # CAS Stored Canonical JSON
    print("\n[CAS Stored Canonical Definition]")
    try:
        definition_json = json.loads(retrieved.raw_bytes.decode("utf-8"))
        print(json.dumps(definition_json, indent=2))
    except Exception as e:
        print(f"  Failed to parse JSON: {e}")

    print("=" * 72)
    return 0


def cmd_explain(ctx: LCSContext, args: argparse.Namespace) -> int:
    """Explains trust policy decision and verification evidence for a capability or interface."""
    urn = args.urn.strip()

    cur = ctx.conn.cursor()
    # If a capability URN was provided, find its bound interface
    target_interface_urn = urn
    if urn.startswith("urn:lcs:tool:") or urn.startswith("urn:lcs:skill:"):
        cur.execute("SELECT interface_urn FROM interface_capability_bindings WHERE capability_urn = ?;", (urn,))
        row = cur.fetchone()
        if not row:
            print(f"Error: Capability '{urn}' is not bound to any interface.", file=sys.stderr)
            return 1
        target_interface_urn = row[0]

    # Check if interface declaration exists
    cur.execute("""
        SELECT i.interface_urn, i.agent_urn, i.interface_version, e.lifecycle_state
        FROM interface_declarations i
        LEFT JOIN entity_urn_registry e ON i.interface_urn = e.entity_urn
        WHERE i.interface_urn = ?;
    """, (target_interface_urn,))
    iface_row = cur.fetchone()
    if not iface_row:
        print(f"Error: Interface '{target_interface_urn}' is not registered in LCS.", file=sys.stderr)
        return 1

    trust_policy = InterfaceTrustPolicy(
        policy_name="operator-explain-policy",
        allowed_attester_ids={"urn:lcs:attester:security:local-authority"},
        min_interface_version=1,
        require_attestation=True,
        require_all_capabilities_verified=True
    )

    decision = ctx.iface_service.evaluate_policy(
        interface_urn=target_interface_urn,
        policy=trust_policy
    )

    print("=" * 72)
    print(" LIVING CAPABILITY SYSTEM (LCS) — POLICY DECISION EXPLANATION")
    print("=" * 72)
    print(f"  Target Query URN:        {urn}")
    print(f"  Evaluated Interface:     {target_interface_urn}")
    print(f"  Owning Agent URN:        {iface_row[1]}")
    print(f"  Interface Version:       {iface_row[2]}")
    print(f"  Lifecycle State:         {iface_row[3]}")
    print(f"  Policy Enforcement:      {decision.decision}")
    print(f"  Verified Trust Status:   {decision.status}")
    print(f"  Attestation ID:          {decision.attestation_id or '(none)'}")

    print("\n[Step-by-Step Verification Audit Evidence]")
    for i, r in enumerate(decision.reasons, start=1):
        print(f"  {i}. {r}")

    print("\n" + "=" * 72)
    return 0


def cmd_profile(ctx: LCSContext, args: argparse.Namespace) -> int:
    """Inspects the structured, evidence-grounded semantic profile of a registered capability."""
    urn = args.urn.strip()
    try:
        parse_canonical_urn(urn)
    except Exception as e:
        print(f"Error: Invalid canonical URN '{urn}': {e}", file=sys.stderr)
        return 1

    try:
        profile = ctx.profile_service.get_profile(urn)
        formatted_text = ctx.profile_service.format_profile_text(profile)
        print(formatted_text)
        return 0
    except CapabilityNotFoundError as e:
        print(f"Error: Capability '{urn}' is not registered in LCS.", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error generating semantic profile for '{urn}': {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


def cmd_match(ctx: LCSContext, args: argparse.Namespace) -> int:
    """Finds and ranks capabilities matching a natural language task description."""
    query = args.query.strip()
    if not query:
        print("Error: Task description query cannot be empty.", file=sys.stderr)
        return 1

    limit = getattr(args, "limit", 5)
    threshold = getattr(args, "threshold", 0.25)
    engine_ver = getattr(args, "engine", "v1.1")

    engine = ctx.retrieval_engine_v1 if engine_ver == "v1" else ctx.retrieval_engine_v11

    result = engine.retrieve(
        query=query,
        limit=limit,
        min_score_threshold=threshold
    )

    formatted_output = engine.format_cli_output(result)
    print(formatted_output)
    return 0


def cmd_params(ctx: LCSContext, args: argparse.Namespace) -> int:
    """Inspects parameter requirements, maps input arguments, and evaluates readiness for a capability."""
    urn = args.urn.strip()
    try:
        parse_canonical_urn(urn)
    except Exception as e:
        print(f"Error: Invalid canonical URN '{urn}': {e}", file=sys.stderr)
        return 1

    user_input = args.input or ""
    if getattr(args, "json_input", None):
        try:
            user_input = json.loads(args.json_input)
        except Exception as e:
            print(f"Error: Failed to parse --json argument as JSON: {e}", file=sys.stderr)
            return 1

    try:
        result = ctx.parameter_engine.evaluate_readiness(
            capability=urn,
            user_input=user_input
        )
        if getattr(args, "raw_json", False):
            print(json.dumps(result.to_dict(), indent=2))
        else:
            print(ctx.parameter_engine.format_cli_output(result))
        return 0
    except CapabilityNotFoundError:
        print(f"Error: Capability '{urn}' is not registered in LCS.", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error evaluating parameters for '{urn}': {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


def cmd_plan(ctx: LCSContext, args: argparse.Namespace) -> int:
    """Synthesizes an explainable, dependency-aware multi-capability execution plan."""
    query = (args.query or "").strip()
    if not query:
        print("Error: Request query cannot be empty.", file=sys.stderr)
        return 1

    user_args = None
    if getattr(args, "json_args", None):
        try:
            user_args = json.loads(args.json_args)
        except Exception as e:
            print(f"Error parsing --args JSON: {e}", file=sys.stderr)
            return 1

    try:
        plan = ctx.planning_engine.create_plan(
            query=query,
            user_arguments=user_args
        )
        if getattr(args, "raw_json", False):
            print(json.dumps(plan.to_dict(), indent=2))
        else:
            print(ctx.planning_engine.format_cli_output(plan))
        return 0
    except Exception as e:
        print(f"Error generating plan for '{query}': {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


def cmd_approve(ctx: LCSContext, args: argparse.Namespace) -> int:
    """Evaluates and authorizes an execution plan under Execution Governance V1."""
    query = (args.query or "").strip()
    if not query:
        print("Error: Plan query or plan ID cannot be empty.", file=sys.stderr)
        return 1

    user_args = None
    if getattr(args, "json_args", None):
        try:
            user_args = json.loads(args.json_args)
        except Exception as e:
            print(f"Error parsing --args JSON: {e}", file=sys.stderr)
            return 1

    try:
        plan = ctx.planning_engine.create_plan(query=query, user_arguments=user_args)
        eval_result = ctx.governance_engine.evaluate_plan(plan)
        print(eval_result.presentation_text)

        if eval_result.gate_1_status != "VERIFIED":
            print("\n[GOVERNANCE BLOCKED]")
            print(f"  Plan '{plan.plan_id}' cannot be authorized due to policy violations:")
            for r in eval_result.reasons:
                print(f"  * {r}")
            return 1

        # Check explicit consent
        principal = getattr(args, "approver", None) or "human-operator@local"
        auto_yes = getattr(args, "yes", False)

        if not auto_yes:
            try:
                ans = input("Authorize this plan for execution? [y/N]: ").strip().lower()
                if ans not in ("y", "yes"):
                    print("\n[GOVERNANCE REJECTED] Authorization declined by operator.")
                    return 1
            except (EOFError, KeyboardInterrupt):
                print("\n[GOVERNANCE REJECTED] Operation aborted.")
                return 1

        consent = ApproverConsent(
            principal=principal,
            role=ApproverRole.HUMAN_OPERATOR,
            method="CLI_AUTO_FLAG" if auto_yes else "CLI_INTERACTIVE_CONFIRMATION"
        )
        token, _ = ctx.governance_engine.approve_plan(plan, approver=consent)

        print("\n[GOVERNANCE APPROVED]")
        print(f"  Token ID:            {token.token_id}")
        print(f"  Plan Integrity Hash: {token.plan_integrity_hash}")
        print(f"  Policy Revision:     {token.policy_context.get('policy_revision_id')}")
        print(f"  Expires At:          {token.exp}")

        if getattr(args, "raw_json", False):
            print(json.dumps(token.to_dict(), indent=2))
        return 0
    except Exception as e:
        print(f"Governance approval error: {e}", file=sys.stderr)
        return 1


def cmd_audit_log_verify(ctx: LCSContext, args: argparse.Namespace) -> int:
    """Cryptographically verifies the append-only hash-chained audit ledger."""
    print("=" * 72)
    print(" LIVING CAPABILITY SYSTEM (LCS) — AUDIT LEDGER VERIFICATION")
    print("=" * 72)
    try:
        ok, count, msg = ctx.governance_engine.audit_ledger.verify_ledger()
        if ok:
            print(f"\n[VERIFIED] {msg}")
            print(f"  Total Valid Records: {count}")
            print(f"  Log File:            {ctx.governance_engine.audit_ledger.log_path}")
            print(f"  Head Anchor:         {ctx.governance_engine.audit_ledger.anchor_path}")
            return 0
        else:
            print(f"\n[FAILED] Verification failed: {msg}", file=sys.stderr)
            return 1
    except Exception as e:
        print(f"\n[ERROR] Audit ledger verification error: {e}", file=sys.stderr)
        return 1


def cmd_skill_discover(ctx: LCSContext, args: argparse.Namespace) -> int:
    """Discovers, ingests, understands, and indexes skills across environments."""
    print("=" * 72)
    print(" LIVING CAPABILITY SYSTEM (LCS) — SKILL INTELLIGENCE DISCOVERY")
    print("=" * 72)
    env_origin = None
    if getattr(args, "environment", None):
        try:
            env_origin = EnvironmentOrigin(args.environment.upper())
        except ValueError:
            print(f"Unknown environment: {args.environment}", file=sys.stderr)
            return 1

    records = ctx.skill_service.run_full_pipeline(environment=env_origin)
    print(f"\nDiscovered & Processed {len(records)} artifacts:")
    rows = []
    for r in records:
        rows.append([
            r.name,
            r.taxonomy_kind.value,
            r.environment_origin.value,
            r.precedence_tier.name,
            r.lifecycle_state.value,
            r.raw_content_digest[:12] + "..."
        ])
    print(_format_table(rows, ["Name", "Taxonomy", "Origin", "Tier", "State", "Content SHA"]))
    return 0


def cmd_skill_list(ctx: LCSContext, args: argparse.Namespace) -> int:
    """Lists registered skill artifacts."""
    tax = getattr(args, "kind", None)
    state = getattr(args, "state", None)
    tax_kind = ArtifactTaxonomyKind(tax.upper()) if tax else None
    life_state = SkillLifecycleState(state.upper()) if state else None

    items = ctx.skill_service.list_artifacts(taxonomy_kind=tax_kind, lifecycle_state=life_state)
    print(f"Registered Artifacts: {len(items)}\n")
    rows = []
    for item in items:
        rows.append([
            item["canonical_urn"],
            item["taxonomy_kind"],
            item["environment_origin"],
            item["lifecycle_state"],
            item["last_updated_at"][:19]
        ])
    print(_format_table(rows, ["Canonical URN", "Taxonomy", "Origin", "State", "Updated At"]))
    return 0


def cmd_skill_inspect(ctx: LCSContext, args: argparse.Namespace) -> int:
    """Inspects detailed state of a registered skill artifact."""
    urn = args.urn
    data = ctx.skill_service.inspect_artifact(urn)
    if not data:
        print(f"Error: No artifact found for URN '{urn}'", file=sys.stderr)
        return 1

    print("=" * 72)
    print(f" SKILL ARTIFACT: {data['display_name']} ({data['canonical_urn']})")
    print("=" * 72)
    print(f"  Artifact ID:     {data['artifact_id']}")
    print(f"  Taxonomy Kind:   {data['taxonomy_kind']}")
    print(f"  Origin:          {data['environment_origin']}")
    print(f"  Precedence Tier: {PrecedenceTier(data['precedence_tier']).name}")
    print(f"  Lifecycle State: {data['lifecycle_state']}")
    print(f"  Source Path:     {data['source_path']}")
    print(f"  Resolved Path:   {data['resolved_path']}")
    print(f"  File Size:       {data['file_size_bytes']} bytes")
    print(f"  Content Digest:  {data['raw_content_digest']}")
    if data["is_bundle"]:
        print(f"  Bundle Manifest: {data['bundle_manifest_digest']}")

    if data["quarantine_reasons"]:
        print(f"  Quarantine:      {', '.join(data['quarantine_reasons'])}")

    if data.get("semantic_profile"):
        prof = data["semantic_profile"]
        print("\n[Semantic Profile]")
        print(f"  Description:     {prof.get('description', {}).get('value', 'N/A')}")
        inputs = prof.get("inputs", {}).get("value") or []
        print(f"  Parameters ({len(inputs)}):")
        for p in inputs:
            req_str = "REQUIRED" if p.get("required") else "optional"
            print(f"    - {p.get('name')} ({p.get('type')}, {req_str}, evidence: {p.get('evidence')}): {p.get('description') or ''}")

    return 0


def cmd_skill_search(ctx: LCSContext, args: argparse.Namespace) -> int:
    """Searches capabilities using the Unified Retrieval Coordinator."""
    tax = getattr(args, "kind", None)
    tax_kind = [ArtifactTaxonomyKind(tax.upper())] if tax else None
    limit = getattr(args, "limit", 10)
    query = args.query

    results = ctx.skill_service.search(query=query, limit=limit, taxonomy_kinds=tax_kind)
    print(f"Search Results for '{query}': {len(results)}\n")
    rows = []
    for r in results:
        rows.append([
            f"{r.relevance_score:.2f}",
            r.display_name,
            r.taxonomy_kind.value,
            r.environment_origin.value,
            r.capability_urn
        ])
    print(_format_table(rows, ["Score", "Name", "Taxonomy", "Origin", "Capability URN"]))
    return 0


def cmd_execute(ctx: LCSContext, args: argparse.Namespace) -> int:
    """Executes an authorized execution plan using an issued EAT token."""
    print("=" * 72)
    print(" LIVING CAPABILITY SYSTEM (LCS) — RUNTIME EXECUTION ENGINE")
    print("=" * 72)

    query = getattr(args, "query", None)
    token_id = getattr(args, "token_id", None)
    plan = None
    token = None

    if query:
        user_args = None
        if getattr(args, "json_args", None):
            try:
                user_args = json.loads(args.json_args)
            except Exception as e:
                print(f"Error parsing --args JSON: {e}", file=sys.stderr)
                return 1

        # Synthesize plan
        plan = ctx.planning_engine.create_plan(query=query, user_arguments=user_args)
        if plan.status != "PLAN_READY":
            print(f"Error: Synthesized plan is not in PLAN_READY state: {plan.status}", file=sys.stderr)
            return 1

        # Evaluate and approve
        consent = ApproverConsent(
            principal=getattr(args, "approver", "human-operator@local"),
            role=ApproverRole.HUMAN_OPERATOR,
            method="CLI_AUTO_EXECUTION"
        )
        active_policy = None
        if getattr(args, "permissive", False):
            active_policy = InterfaceTrustPolicy(
                policy_name="cli-permissive-policy",
                min_interface_version=1,
                require_attestation=False,
                require_all_capabilities_verified=False
            )
        elif getattr(args, "policy_name", None):
            active_policy = InterfaceTrustPolicy(
                policy_name=args.policy_name,
                min_interface_version=1,
                require_attestation=False,
                require_all_capabilities_verified=False
            )
        try:
            token, eval_res = ctx.governance_engine.approve_plan(
                plan=plan,
                approver=consent,
                active_policy=active_policy
            )
        except Exception as e:
            print(f"Error: Governance approval failed: {e}", file=sys.stderr)
            return 1
    elif token_id:
        print("Error: Direct execution by --token requires plan context. Use query syntax.", file=sys.stderr)
        return 1
    else:
        print("Error: Specify a task query to execute.", file=sys.stderr)
        return 1

    try:
        res = ctx.execution_engine.execute_plan(plan=plan, token=token)
        print(f"\n[EXECUTION {res.lifecycle_state.value}]")
        print(f"  Run ID:              {res.run_id}")
        print(f"  Plan ID:             {res.plan_id}")
        print(f"  Token ID:            {res.token_id}")
        print(f"  Permit ID:           {res.permit_id}")
        print(f"  Duration:            {res.duration_ms:.2f} ms")
        print(f"  Completed Steps:     {res.completed_steps}/{res.total_steps}")
        print(f"  Trace CAS Digest:    {res.trace_cas_digest}")

        print("\nStep Execution Summary:")
        rows = []
        for s in res.step_records:
            rows.append([
                str(s.step_index),
                s.step_id,
                s.status.value,
                f"{s.duration_ms:.1f}ms" if s.duration_ms else "N/A",
                str(s.retry_count),
                s.capability_urn
            ])
        print(_format_table(rows, ["#", "Step ID", "Status", "Duration", "Retries", "Capability URN"]))

        if res.outputs:
            print("\nFinal Outputs:")
            for s_id, out in res.outputs.items():
                print(f"  [{s_id}]: {json.dumps(out, indent=4)}")

        if res.lifecycle_state.value != "SUCCEEDED":
            if res.error_message:
                print(f"\nExecution Error: {res.error_message}", file=sys.stderr)
            return 1

        if getattr(args, "raw_json", False):
            print(json.dumps(res.to_dict(), indent=2))
        return 0
    except Exception as e:
        print(f"\nExecution failed: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


def cmd_run_inspect(ctx: LCSContext, args: argparse.Namespace) -> int:
    """Inspects detailed step-by-step logs and outputs of an execution run."""
    run_id = args.run_id.strip()
    data = ctx.execution_engine.get_run(run_id)
    if not data:
        print(f"Error: Execution run '{run_id}' not found.", file=sys.stderr)
        return 1

    print("=" * 72)
    print(f" EXECUTION RUN: {data['run_id']} ({data['lifecycle_state']})")
    print("=" * 72)
    print(f"  Plan ID:          {data['plan_id']}")
    print(f"  Token ID:         {data['token_id']}")
    print(f"  Permit ID:        {data['permit_id']}")
    print(f"  Completed Steps:  {data['completed_steps']}/{data['total_steps']}")
    print(f"  Trace CAS Digest: {data['trace_cas_digest']}")
    if data['error_message']:
        print(f"  Error Message:    {data['error_message']}")

    print("\nSteps:")
    for s in data["steps"]:
        print(f"  * [{s['step_index']}] {s['step_id']} -> {s['status']} ({s['duration_ms']:.1f}ms)")
        print(f"    Capability: {s['capability_urn']}")
        print(f"    Input CAS:  {s['input_cas_digest']}")
        if s['output_cas_digest']:
            print(f"    Output CAS: {s['output_cas_digest']}")
        if s['error_details']:
            print(f"    Error:      {s['error_details']}")
    return 0


def cmd_run_list(ctx: LCSContext, args: argparse.Namespace) -> int:
    """Lists recent execution runs."""
    limit = getattr(args, "limit", 20)
    runs = ctx.execution_engine.list_runs(limit=limit)
    print(f"Recent Execution Runs: {len(runs)}\n")
    rows = []
    for r in runs:
        rows.append([
            r["run_id"],
            r["plan_id"],
            r["lifecycle_state"],
            f"{r['completed_steps']}/{r['total_steps']}",
            f"{r['error_message'][:30]}..." if r["error_message"] else "None"
        ])
    print(_format_table(rows, ["Run ID", "Plan ID", "State", "Steps", "Error"]))
    return 0


def cmd_serve_mcp(ctx: LCSContext, args: argparse.Namespace) -> int:
    """Runs LCS as a standard JSON-RPC 2.0 stdio MCP server."""
    from .mcp_server import run_mcp_server
    return run_mcp_server(ctx=ctx)


def cmd_dashboard(ctx: LCSContext, args: argparse.Namespace) -> int:
    """Launches the LCS Web Telemetry & Capability Dashboard."""
    from .dashboard import run_dashboard
    host = getattr(args, "host", "127.0.0.1")
    port = getattr(args, "port", 8765)
    open_browser = getattr(args, "open_browser", False)
    run_dashboard(host=host, port=port, open_browser=open_browser, ctx=ctx)
    return 0


def cmd_call_me(ctx: LCSContext, args: argparse.Namespace) -> int:
    if getattr(args, "handoff", False):
        args.raw_json = True
        return cmd_inventory_context(ctx, args)
    """Invokes the thin /call-me entry point with a natural-language task."""
    raw_instruction = args.task
    if not raw_instruction or not raw_instruction.strip():
        print("Error: Task description cannot be empty.", file=sys.stderr)
        return 1

    do_execute = getattr(args, "execute", False)
    out_file = getattr(args, "output", None)
    call_inputs = {"output_file": out_file, "deliverable": out_file} if out_file else None
    resp = ctx.call_me.execute_call_me(
        f"/call-me {raw_instruction}",
        session_id=getattr(args, "session_id", None),
        execute=do_execute,
        inputs=call_inputs,
        approver_consent=(ApproverConsent(principal=getpass.getuser(),
                             role=ApproverRole.HUMAN_OPERATOR, method="CLI_EXECUTE_FLAG")
                            if do_execute else None)
    )

    if not resp:
        print("Error: /call-me entry point returned no response.", file=sys.stderr)
        return 1

    if getattr(args, "raw_json", False):
        if hasattr(resp, "to_dict"):
            print(json.dumps(resp.to_dict(), indent=2))
            return 0 if resp.status == "ACCEPTED" else 1
        print(json.dumps(resp, indent=2))
        return 0 if resp.get("status") in ("ACCEPTED", "SUCCEEDED") else 1

    if do_execute and isinstance(resp, dict):
        print("=" * 72)
        print(" LIVING CAPABILITY SYSTEM (LCS) — /call-me MULTI-STEP EXECUTION")
        print("=" * 72)
        print(f"  Execution Status:   {resp.get('status')}")
        print(f"  Run ID:             {resp.get('run_id')}")
        print(f"  Plan ID:            {resp.get('plan_id')}")
        print(f"  Lifecycle State:    {resp.get('lifecycle_state')}")
        print(f"  Steps Completed:    {resp.get('completed_steps')} / {resp.get('total_steps')}")
        print(f"  Trace CAS Digest:   {resp.get('trace_cas_digest')}")

        if resp.get("capabilities_used"):
            print("\nCapabilities Used in Execution:")
            for cap in resp["capabilities_used"]:
                print(f"  * {cap}")

        if resp.get("step_records"):
            print("\nExecution Step Records:")
            for s in resp["step_records"]:
                print(f"  [{s.get('status')}] {s.get('step_id')} ({s.get('duration_ms', 0):.1f}ms) -> {s.get('capability_urn')}")

        if resp.get("error_message"):
            print(f"\nExecution Error: {resp['error_message']}", file=sys.stderr)

        return 0 if resp.get("status") == "SUCCEEDED" else 1

    print("=" * 72)
    print(" LIVING CAPABILITY SYSTEM (LCS) — /call-me INVOCATION")
    print("=" * 72)
    print(f"  Request ID:         {resp.request_id}")
    print(f"  Session ID:         {resp.session_id}")
    print(f"  Status:             {resp.status}")
    print(f"  Governance:         {resp.governance_status}")
    print(f"  Matched Candidates: {resp.candidate_count}")
    print(f"  Message:            {resp.message}")

    if resp.candidate_urns:
        print("\nCandidate Capabilities:")
        for urn in resp.candidate_urns:
            print(f"  * {urn}")

    if resp.error_details:
        print(f"\nError Details: {resp.error_details}", file=sys.stderr)

    return 0 if resp.status == "ACCEPTED" else 1


def cmd_install_command(ctx: LCSContext, args: argparse.Namespace) -> int:
    """Installs host-specific /call-me slash-command artifacts."""
    env = getattr(args, "environment", "all").lower()
    is_global = getattr(args, "is_global", False)
    overwrite = getattr(args, "overwrite", False)
    workspace = ctx.inventory.workspace_root

    print("=" * 72)
    print(" LCS SLASH-COMMAND INSTALLER")
    print("=" * 72)

    installed = {}
    try:
        if env in ("codex", "all") and is_global:
            root = os.path.expanduser("~")
            installed["Codex ($call-me)"] = ctx.command_generator.install_antigravity(root, overwrite=overwrite)
        elif env == "codex":
            installed["Codex ($call-me)"] = ctx.command_generator.install_antigravity(workspace, overwrite=overwrite)

        if env in ("antigravity", "all"):
            p = ctx.command_generator.install_antigravity(workspace, is_global=is_global, overwrite=overwrite)
            installed["Antigravity (.agents/skills/call-me/SKILL.md)"] = p
        if env in ("claude_code", "claude", "all"):
            p = ctx.command_generator.install_claude_code(workspace, is_global=is_global, overwrite=overwrite)
            installed["Claude Code (.claude/commands/call-me.md)"] = p
        if env in ("opencode", "all"):
            p = ctx.command_generator.install_opencode(workspace, overwrite=overwrite)
            installed["OpenCode (.opencode/commands/call-me.md)"] = p
    except Exception as e:
        print(f"  [!] Installation Error: {e}", file=sys.stderr)
        return 1

    for name, path in installed.items():
        print(f"  [+] Installed {name}: {path}")

    return 0


def cmd_uninstall_command(ctx: LCSContext, args: argparse.Namespace) -> int:
    """Uninstalls host-specific /call-me slash-command artifacts."""
    env = getattr(args, "environment", "all").lower()
    is_global = getattr(args, "is_global", False)
    workspace = ctx.inventory.workspace_root

    print("=" * 72)
    print(" LCS SLASH-COMMAND UNINSTALLER")
    print("=" * 72)

    if env == "all":
        targets = ["antigravity", "claude_code", "opencode", "codex"] if is_global else ["antigravity", "claude_code", "opencode"]
    else:
        targets = [env]
    for target in targets:
        success = ctx.command_generator.uninstall(workspace, target, is_global=is_global)
        status = "REMOVED" if success else "NOT FOUND / SKIPPED"
        print(f"  [-] {target.upper()}: {status}")

    return 0


def cmd_setup(args: argparse.Namespace) -> int:
    """Handles 'lcs setup' command for local-first setup, doctor check, and repair."""
    is_project = getattr(args, "is_project", False)
    is_global = not is_project
    check_only = getattr(args, "check", False) or getattr(args, "doctor", False)
    repair_mode = getattr(args, "repair", False)
    overwrite = getattr(args, "force", False) or getattr(args, "overwrite", False)
    env_str = getattr(args, "environment", "all")
    envs = [env_str] if env_str != "all" else ["all"]
    as_json = getattr(args, "raw_json", False)
    root_override = getattr(args, "root", None)

    if check_only:
        res = SetupEngine.run_check(
            is_global=is_global,
            workspace_root=os.getcwd(),
            root_override=root_override
        )
    elif repair_mode:
        res = SetupEngine.run_repair(
            is_global=is_global,
            workspace_root=os.getcwd(),
            environments=envs,
            overwrite=overwrite,
            root_override=root_override
        )
    else:
        res = SetupEngine.run_setup(
            is_global=is_global,
            workspace_root=os.getcwd(),
            environments=envs,
            overwrite=overwrite,
            root_override=root_override
        )

    if as_json:
        print(json.dumps(res, indent=2))
        return 0 if res["status"] in ("SUCCESS", "WARNING") else 1

    # Formatted terminal output
    print("=" * 72)
    if check_only:
        print(" LIVING CAPABILITY SYSTEM (LCS) — SETUP DIAGNOSTICS & DOCTOR")
    elif repair_mode:
        print(" LIVING CAPABILITY SYSTEM (LCS) — SYSTEM REPAIR")
    else:
        print(" LIVING CAPABILITY SYSTEM (LCS) — LOCAL INSTALLATION & SETUP")
    print("=" * 72)

    scope = "User-Global (~/.lcs)" if is_global else "Project-Local (./.lcs)"
    print(f"\n[Target Configuration]")
    print(f"  Scope:             {scope}")
    print(f"  State Directory:   {res['root_dir']}")
    print(f"  Database Path:     {res['db_path']}")
    print(f"  Overall Health:    {res['overall_health']}")

    if "repaired_items" in res and res["repaired_items"]:
        print("\n[Repairs Executed]")
        for item in res["repaired_items"]:
            print(f"  [+] {item}")

    if "installed_integrations" in res:
        print("\n[Agent Integrations]")
        for ag_name, info in res["installed_integrations"].items():
            st = info.get("status")
            p = info.get("path") or "(none)"
            if st == "INSTALLED":
                print(f"  [+] {ag_name.upper()}: INSTALLED -> {p}")
            elif st == "CONFLICT_SKIPPED":
                print(f"  [!] {ag_name.upper()}: CONFLICT PRESERVED -> {p} (use --force to overwrite)")
            else:
                msg = info.get("message", "")
                print(f"  [-] {ag_name.upper()}: {st} -> {msg}")

    print("\n[Health Diagnostics]")
    for d in res.get("diagnostics", []):
        icon = "[+]" if d["status"] == "PASS" else ("[?]" if d["status"] == "WARN" else "[!]")
        print(f"  {icon} [{d['category']}] {d['name']}: {d['message']}")
        if d.get("remediation") and d["status"] != "PASS":
            print(f"      Remediation: {d['remediation']}")

    print("=" * 72)
    return 0 if res["status"] in ("SUCCESS", "WARNING") else 1


def cmd_inventory_scan(ctx: LCSContext, args: argparse.Namespace) -> int:
    """Scans and synchronizes capabilities across all active environment adapters."""
    print("=" * 72)
    print(" LIVING CAPABILITY SYSTEM — UNIFIED CAPABILITY INVENTORY SCAN")
    print("=" * 72)
    adapters = ctx.adapter_registry.list_all() if hasattr(ctx, "adapter_registry") else []
    summary = ctx.inventory.initialize_environment(adapters=adapters)
    print(f"Total Discovered Resources: {ctx.inventory.total_count}")
    print("\nBreakdown by Resource Type:")
    for k, v in sorted(summary.items()):
        print(f"  * {k:<20}: {v}")

    conflicts = ctx.inventory.get_conflicts()
    if conflicts:
        print(f"\nResolved Precedence Conflicts: {len(conflicts)}")
        for c in conflicts[:5]:
            print(f"  - {c.name}: {c.resolution_reason}")
    print("=" * 72)
    return 0


def cmd_inventory_list(ctx: LCSContext, args: argparse.Namespace) -> int:
    """Lists registered capabilities in the Unified Inventory."""
    rtype = None
    if getattr(args, "type", None):
        try:
            from .inventory import ResourceType
            rtype = ResourceType(args.type.upper())
        except Exception:
            print(f"Error: Unknown resource type '{args.type}'", file=sys.stderr)
            return 1

    records = ctx.inventory.list_all(resource_type=rtype)
    if not records:
        adapters = ctx.adapter_registry.list_all() if hasattr(ctx, "adapter_registry") else []
        ctx.inventory.initialize_environment(adapters=adapters)
        records = ctx.inventory.list_all(resource_type=rtype)

    limit = getattr(args, "limit", 50)
    print("=" * 72)
    print(f" UNIFIED CAPABILITY INVENTORY ({len(records)} resources found)")
    print("=" * 72)
    print(f"{'Type':<12} | {'State':<12} | {'Name':<24} | {'URN'}")
    print("-" * 72)
    for r in records[:limit]:
        print(f"{r.resource_type.value:<12} | {r.lifecycle_state.value:<12} | {r.name[:24]:<24} | {r.urn}")
    if len(records) > limit:
        print(f"... and {len(records) - limit} more (use --limit to expand)")
    print("=" * 72)
    return 0


def cmd_inventory_inspect(ctx: LCSContext, args: argparse.Namespace) -> int:
    """Inspects a unified capability resource and its deep retrieval details."""
    urn = args.urn.strip()
    rec = ctx.inventory.get_by_urn(urn)
    if not rec:
        matches = ctx.inventory.search(urn, limit=1)
        if matches:
            rec = matches[0]

    if not rec:
        adapters = ctx.adapter_registry.list_all() if hasattr(ctx, "adapter_registry") else []
        ctx.inventory.initialize_environment(adapters=adapters)
        rec = ctx.inventory.get_by_urn(urn)
        if not rec:
            matches = ctx.inventory.search(urn, limit=1)
            if matches:
                rec = matches[0]

    if not rec:
        print(f"Error: Resource '{urn}' not found in unified inventory.", file=sys.stderr)
        return 1

    try:
        retrieval = ctx.deep_retriever.retrieve_deep(rec.urn)
    except Exception as e:
        print(f"Error retrieving deep resource '{urn}': {e}", file=sys.stderr)
        return 1

    print("=" * 72)
    print(" UNIFIED CAPABILITY RECORD INSPECTION")
    print("=" * 72)
    print(f"  URN:                 {rec.urn}")
    print(f"  Name:                {rec.name}")
    print(f"  Type:                {rec.resource_type.value}")
    print(f"  Lifecycle State:     {rec.lifecycle_state.value}")
    print(f"  Origin Host:         {rec.provenance.origin_host}")
    print(f"  Precedence Tier:     {rec.provenance.precedence_tier}")
    print(f"  Content Digest:      {rec.raw_content_digest}")
    print(f"  Resolved Path:       {rec.provenance.resolved_path}")
    print(f"  Runtime Env:         {rec.execution_requirements.runtime_environment}")
    print(f"  Required Binaries:   {', '.join(rec.execution_requirements.required_binaries) or 'None'}")
    print(f"  Host Compatible:     {retrieval.compatibility_passed}")
    print(f"  Executable:          {retrieval.is_executable}")

    if retrieval.resolved_dependencies:
        print("\n[Resolved Dependencies]")
        for d in retrieval.resolved_dependencies:
            print(f"  * {d.name} ({d.resource_type.value}) -> {d.urn}")

    if retrieval.missing_dependencies:
        print("\n[Missing Dependencies]")
        for m in retrieval.missing_dependencies:
            print(f"  ! {m}")

    if rec.security_flags:
        print(f"\n[Security Audit Flags]: {', '.join(rec.security_flags)}")

    print("=" * 72)
    return 0


def cmd_inventory_context(ctx: LCSContext, args: argparse.Namespace) -> int:
    """Builds a token-optimized context transfer payload for model or subagent delegation."""
    task = args.task.strip()
    budget = getattr(args, "budget", None)

    if ctx.inventory.total_count == 0:
        adapters = ctx.adapter_registry.list_all() if hasattr(ctx, "adapter_registry") else []
        ctx.inventory.initialize_environment(adapters=adapters)

    from .inventory.models import ResourceType
    handoff = getattr(args, "handoff", False)
    matches = (record for record in ctx.inventory.search(
        task, limit=2 if handoff else 1, resource_types=[ResourceType.SKILL] if handoff else None
    ) if not handoff or record.name != "call-me")
    primary = next(matches, None)
    if primary is None:
        print(f"Error: Zero registered capabilities matched task '{task}'.", file=sys.stderr)
        return 1

    host = ctx.get_active_adapter().kind.value
    retrieval = ctx.deep_retriever.retrieve_deep(primary.urn, active_environment=host)
    payload = ctx.deep_retriever.optimize_context_transfer(
        task_query=task,
        retrieval_result=retrieval,
        token_budget=budget
    )

    required = {primary.urn}
    stack = [primary]
    by_identity = {
        identity: record
        for record in retrieval.resolved_dependencies
        for identity in (record.name, record.urn)
    }
    while stack:
        for edge in stack.pop().declared_dependencies:
            dependency = by_identity.get(edge.get("name"))
            if edge.get("mandatory", True) and dependency and dependency.urn not in required:
                required.add(dependency.urn)
                stack.append(dependency)
    missing = [record.name for record in retrieval.resolved_dependencies
               if record.urn in required and record.name not in payload.dependency_snippets]
    all_missing = sorted(set(retrieval.missing_dependencies + missing))
    ready = retrieval.is_executable and not all_missing and not payload.budget_exceeded

    block_reason = None
    if not ready:
        if not retrieval.is_executable or all_missing:
            block_reason = f"Missing or inaccessible required resources: {all_missing}"
        elif payload.budget_exceeded:
            block_reason = f"Token budget exceeded: estimated {payload.estimated_tokens} tokens exceeds budget limit of {payload.token_budget_limit}"

    if getattr(args, "raw_json", False):
        print(json.dumps({
            "ready": ready,
            "host": host,
            "block_reason": block_reason,
            "missing_required": all_missing,
            "instructions": payload.instructions_text if ready else "",
            "dependencies": payload.dependency_snippets if ready else {},
            "task_query": payload.task_query,
            "primary_urn": payload.primary_urn,
            "estimated_tokens": payload.estimated_tokens,
            "token_metric": "ESTIMATE",
            "budget_limit": payload.token_budget_limit,
            "budget_exceeded": payload.budget_exceeded,
            "omitted_references": payload.omitted_references,
            "provenance_hashes": payload.provenance_hashes
        }, indent=2))
        return 0 if ready else 1

    if not ready:
        print("Required skill context is unavailable or exceeds the budget.", file=sys.stderr)
        return 1
    print("=" * 72)
    print(" TOKEN-OPTIMIZED CONTEXT TRANSFER PAYLOAD")
    print("=" * 72)
    print(f"  Task Query:          {payload.task_query}")
    print(f"  Primary URN:         {payload.primary_urn}")
    print(f"  Estimated Tokens:    {payload.estimated_tokens}")
    if payload.token_budget_limit:
        print(f"  Token Budget Limit:  {payload.token_budget_limit}")
        print(f"  Budget Exceeded:     {payload.budget_exceeded}")
    if payload.omitted_references:
        print(f"  Omitted References:  {len(payload.omitted_references)}")
        for o in payload.omitted_references:
            print(f"    - {o}")
    print("\n--- Guidance Preview ---")
    print(payload.execution_guidance)
    print("\n--- Raw Instructions (First 300 chars) ---")
    print(payload.instructions_text[:300] + ("..." if len(payload.instructions_text) > 300 else ""))
    print("=" * 72)
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="lcs",
        description="Living Capability System (LCS) Command-Line Interface"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "--root",
        help="Path to LCS root directory (default: LCS_ROOT env or ./.lcs)"
    )

    subparsers = parser.add_subparsers(dest="subcommand", help="Available commands")

    # lcs status
    sub_status = subparsers.add_parser("status", help="Display LCS subsystem status and health")
    sub_status.set_defaults(func=cmd_status)

    # lcs discover
    sub_discover = subparsers.add_parser("discover", help="Discover tools from an MCP server")
    sub_discover.add_argument("--server-command", help="Command to run the MCP server (e.g. 'python3 server.py')")
    sub_discover.add_argument("--server-name", help="Logical name of the MCP server (e.g. 'document-tools')")
    sub_discover.add_argument("--policy-name", help="Trust policy name")
    sub_discover.add_argument("--timeout", type=float, default=10.0, help="MCP request timeout in seconds (default: 10.0)")
    sub_discover.add_argument("--env", action="append", help="Pass environment variable to MCP server as KEY=VALUE or KEY")
    sub_discover.add_argument("--allow-env", action="append", help="Allow specific host environment variable to pass to MCP server")
    sub_discover.set_defaults(func=cmd_discover)

    # lcs search
    sub_search = subparsers.add_parser("search", help="Search capabilities using natural language FTS5")
    sub_search.add_argument("query", help="Search query string")
    sub_search.add_argument("--limit", type=int, default=10, help="Maximum number of results to return (default: 10)")
    sub_search.add_argument("--status", choices=["VERIFIED", "UNVERIFIED", "REJECTED", "UNAVAILABLE"], help="Filter by trust status")
    sub_search.set_defaults(func=cmd_search)

    # lcs inspect
    sub_inspect = subparsers.add_parser("inspect", help="Inspect a capability definition and metadata")
    sub_inspect.add_argument("urn", help="Canonical capability URN")
    sub_inspect.set_defaults(func=cmd_inspect)

    # lcs explain
    sub_explain = subparsers.add_parser("explain", help="Explain policy evaluation and trust status for a capability or interface")
    sub_explain.add_argument("urn", help="Canonical capability URN or interface URN")
    sub_explain.set_defaults(func=cmd_explain)

    # lcs profile
    sub_profile = subparsers.add_parser("profile", help="Inspect structured evidence-grounded semantic profile of a capability")
    sub_profile.add_argument("urn", help="Canonical capability URN")
    sub_profile.set_defaults(func=cmd_profile)

    # lcs match
    sub_match = subparsers.add_parser("match", help="Find and rank capabilities matching a natural language task description")
    sub_match.add_argument("query", help="Natural language task description")
    sub_match.add_argument("--limit", type=int, default=5, help="Maximum number of matches to return (default: 5)")
    sub_match.add_argument("--threshold", type=float, default=0.25, help="Minimum relevance score threshold (default: 0.25)")
    sub_match.add_argument("--engine", choices=["v1", "v1.1"], default="v1.1", help="Capability retrieval engine version (default: v1.1)")
    sub_match.set_defaults(func=cmd_match)

    # lcs params
    sub_params = subparsers.add_parser("params", help="Inspect and evaluate parameter requirements and input readiness")
    sub_params.add_argument("urn", help="Canonical capability URN")
    sub_params.add_argument("input", nargs="?", default="", help="Natural language request or key-value arguments")
    sub_params.add_argument("--json", dest="json_input", help="Structured JSON dictionary of arguments")
    sub_params.add_argument("--format-json", dest="raw_json", action="store_true", help="Output raw JSON instead of formatted text")
    sub_params.set_defaults(func=cmd_params)

    # lcs plan
    sub_plan = subparsers.add_parser("plan", help="Synthesize an explainable multi-capability execution plan")
    sub_plan.add_argument("query", help="Compound or single task description")
    sub_plan.add_argument("--args", dest="json_args", help="Structured JSON dictionary of user arguments")
    sub_plan.add_argument("--format-json", dest="raw_json", action="store_true", help="Output raw JSON instead of formatted text")
    sub_plan.set_defaults(func=cmd_plan)

    # lcs approve
    sub_approve = subparsers.add_parser("approve", help="Evaluate and authorize a capability execution plan under Governance V1")
    sub_approve.add_argument("query", help="Task query or plan ID to evaluate and approve")
    sub_approve.add_argument("--args", dest="json_args", help="Structured JSON dictionary of user arguments")
    sub_approve.add_argument("--yes", "-y", action="store_true", help="Automatically confirm operator approval")
    sub_approve.add_argument("--approver", help="Approver principal identity (default: human-operator@local)")
    sub_approve.add_argument("--format-json", dest="raw_json", action="store_true", help="Output raw JSON token upon approval")
    sub_approve.set_defaults(func=cmd_approve)

    # lcs audit-log
    sub_audit = subparsers.add_parser("audit-log", help="Inspect and verify the append-only hash-chained audit ledger")
    audit_sub = sub_audit.add_subparsers(dest="audit_action", help="Audit sub-action")
    sub_audit_verify = audit_sub.add_parser("verify", help="Cryptographically verify ledger sequence and anchor integrity")
    sub_audit_verify.set_defaults(func=cmd_audit_log_verify)
    sub_audit.set_defaults(func=cmd_audit_log_verify)

    # lcs skill
    sub_skill = subparsers.add_parser("skill", help="Skill Intelligence commands (discover, list, inspect, search)")
    skill_sub = sub_skill.add_subparsers(dest="skill_action", help="Skill action to execute")

    # lcs skill discover
    sub_skill_disc = skill_sub.add_parser("discover", help="Discover and index skills across all environments")
    sub_skill_disc.add_argument("--environment", choices=["antigravity", "claude_code", "opencode"], help="Filter by environment origin")
    sub_skill_disc.set_defaults(func=cmd_skill_discover)

    # lcs skill list
    sub_skill_list = skill_sub.add_parser("list", help="List registered skill artifacts")
    sub_skill_list.add_argument("--kind", help="Filter by artifact taxonomy kind (SKILL, COMMAND, RULE, etc.)")
    sub_skill_list.add_argument("--state", help="Filter by lifecycle state (AVAILABLE, READ, etc.)")
    sub_skill_list.set_defaults(func=cmd_skill_list)

    # lcs skill inspect
    sub_skill_insp = skill_sub.add_parser("inspect", help="Inspect detailed artifact metadata and semantic profile")
    sub_skill_insp.add_argument("urn", help="Canonical skill URN")
    sub_skill_insp.set_defaults(func=cmd_skill_inspect)

    # lcs skill search
    sub_skill_srch = skill_sub.add_parser("search", help="Search skills and capabilities using Unified Retrieval Coordinator")
    sub_skill_srch.add_argument("query", help="Search query string")
    sub_skill_srch.add_argument("--limit", type=int, default=10, help="Maximum number of results to return (default: 10)")
    sub_skill_srch.add_argument("--kind", help="Filter by taxonomy kind (e.g. SKILL, COMMAND)")
    sub_skill_srch.set_defaults(func=cmd_skill_search)

    # Default fallback for 'lcs skill'
    sub_skill.set_defaults(func=cmd_skill_list)

    # lcs execute
    sub_exec = subparsers.add_parser("execute", help="Execute an authorized plan using Governance V1 token")
    sub_exec.add_argument("query", nargs="?", help="Task query to synthesize, authorize, and execute")
    sub_exec.add_argument("--token", dest="token_id", help="Pre-authorized EAT token ID")
    sub_exec.add_argument("--args", dest="json_args", help="JSON dictionary of user arguments")
    sub_exec.add_argument("--policy", dest="policy_name", help="Trust policy name")
    sub_exec.add_argument("--permissive", dest="permissive", action="store_true", help="Execute under permissive policy (bypasses attestation)")
    sub_exec.add_argument("--approver", default="human-operator@local", help="Approver principal identity")
    sub_exec.add_argument("--format-json", dest="raw_json", action="store_true", help="Output full JSON execution trace")
    sub_exec.set_defaults(func=cmd_execute)

    # lcs run
    sub_run = subparsers.add_parser("run", help="Inspect and list historical execution runs")
    run_sub = sub_run.add_subparsers(dest="run_action", help="Run action to execute")
    sub_run_inspect = run_sub.add_parser("inspect", help="Inspect detailed execution run records")
    sub_run_inspect.add_argument("run_id", help="Execution Run ID")
    sub_run_inspect.set_defaults(func=cmd_run_inspect)
    sub_run_list = run_sub.add_parser("list", help="List recent execution runs")
    sub_run_list.add_argument("--limit", type=int, default=20, help="Maximum number of runs to list")
    sub_run_list.set_defaults(func=cmd_run_list)
    sub_run.set_defaults(func=cmd_run_list)

    # lcs serve-mcp
    sub_mcp = subparsers.add_parser("serve-mcp", help="Run LCS as a standard JSON-RPC 2.0 stdio MCP server")
    sub_mcp.set_defaults(func=cmd_serve_mcp)

    # lcs dashboard
    sub_dash = subparsers.add_parser("dashboard", help="Launch the LCS Web Telemetry & Capability Dashboard")
    sub_dash.add_argument("--host", default="127.0.0.1", help="Host interface to bind to (default: 127.0.0.1)")
    sub_dash.add_argument("--port", type=int, default=8765, help="Port to listen on (default: 8765)")
    sub_dash.add_argument("--open", dest="open_browser", action="store_true", help="Automatically open dashboard in web browser")
    sub_dash.set_defaults(func=cmd_dashboard)

    # lcs call-me (Phase 2A)
    sub_call_me = subparsers.add_parser("call-me", help="Explicit /call-me invocation entry point")
    sub_call_me.add_argument("task", help="Natural language task description")
    sub_call_me.add_argument("--session-id", help="Optional persistent session identifier")
    call_mode = sub_call_me.add_mutually_exclusive_group()
    call_mode.add_argument("--execute", action="store_true", help="Authorize and execute multi-capability pipeline")
    call_mode.add_argument("--handoff", action="store_true", help="Return selected skill instructions for the host")
    sub_call_me.add_argument("--output", help="Optional path to output deliverable artifact")
    sub_call_me.add_argument("--budget", type=int, help="Estimated token budget for the skill handoff")
    sub_call_me.add_argument("--format-json", dest="raw_json", action="store_true", help="Output JSON response")
    sub_call_me.set_defaults(func=cmd_call_me)

    # lcs install-command (Phase 2A)
    sub_inst_cmd = subparsers.add_parser("install-command", help="Install /call-me slash command artifacts into host environments")
    sub_inst_cmd.add_argument("--environment", choices=["codex", "antigravity", "claude_code", "opencode", "all"], default="all", help="Target environment")
    sub_inst_cmd.add_argument("--global", "--is-global", dest="is_global", action="store_true", help="Install to user home directory instead of workspace")
    sub_inst_cmd.add_argument("--overwrite", action="store_true", help="Overwrite existing non-LCS files")
    sub_inst_cmd.set_defaults(func=cmd_install_command)

    # lcs uninstall-command (Phase 2A)
    sub_uninst_cmd = subparsers.add_parser("uninstall-command", help="Remove /call-me slash command artifacts from host environments")
    sub_uninst_cmd.add_argument("--environment", choices=["codex", "antigravity", "claude_code", "opencode", "all"], default="all", help="Target environment")
    sub_uninst_cmd.add_argument("--global", "--is-global", dest="is_global", action="store_true", help="Remove from user home directory instead of workspace")
    sub_uninst_cmd.set_defaults(func=cmd_uninstall_command)

    # lcs inventory (Milestone 1)
    sub_inv = subparsers.add_parser("inventory", help="Unified Capability Inventory & Token-Optimized Retrieval")
    inv_sub = sub_inv.add_subparsers(dest="inventory_action", help="Inventory action")

    # lcs inventory scan
    sub_inv_scan = inv_sub.add_parser("scan", help="Scan and synchronize capabilities across all host environments")
    sub_inv_scan.set_defaults(func=cmd_inventory_scan)

    # lcs inventory list
    sub_inv_list = inv_sub.add_parser("list", help="List registered capability resources in the unified inventory")
    sub_inv_list.add_argument("--type", help="Filter by ResourceType (AGENT, SKILL, TOOL, MCP_SERVER, COMMAND, SCRIPT, etc.)")
    sub_inv_list.add_argument("--limit", type=int, default=50, help="Maximum number of resources to display")
    sub_inv_list.set_defaults(func=cmd_inventory_list)

    # lcs inventory inspect
    sub_inv_insp = inv_sub.add_parser("inspect", help="Inspect a capability record, dependencies, and execution readiness")
    sub_inv_insp.add_argument("urn", help="Canonical URN or name")
    sub_inv_insp.set_defaults(func=cmd_inventory_inspect)

    # lcs inventory context
    sub_inv_ctx = inv_sub.add_parser("context", help="Build token-budget-optimized context transfer payload for a task")
    sub_inv_ctx.add_argument("task", help="Task description or query")
    sub_inv_ctx.add_argument("--budget", type=int, help="Maximum token budget limit")
    sub_inv_ctx.add_argument("--format-json", dest="raw_json", action="store_true", help="Output raw JSON payload")
    sub_inv_ctx.set_defaults(func=cmd_inventory_context)

    sub_inv.set_defaults(func=cmd_inventory_scan)

    # lcs setup (Stage 1 Universal Local Setup)
    sub_setup = subparsers.add_parser("setup", help="Universal local setup, diagnostics, and repairs")
    sub_setup.add_argument("--global", "-g", dest="is_global", action="store_true", default=None, help="Set up user-level global LCS environment (default)")
    sub_setup.add_argument("--project", "-p", dest="is_project", action="store_true", help="Set up project-local environment (./.lcs)")
    sub_setup.add_argument("--check", "--doctor", dest="check", action="store_true", help="Run diagnostic health checks without writing changes")
    sub_setup.add_argument("--repair", action="store_true", help="Repair damaged state directories, missing migrations, or broken commands")
    sub_setup.add_argument("--force", "-f", "--overwrite", dest="force", action="store_true", help="Overwrite conflicting non-LCS command files")
    sub_setup.add_argument("--environment", "-e", choices=["all", "antigravity", "claude_code", "opencode", "codex"], default="all", help="Target agent environment")
    sub_setup.add_argument("--format-json", "--json", dest="raw_json", action="store_true", help="Output results in JSON format")
    sub_setup.set_defaults(func=cmd_setup)

    parsed_args = parser.parse_args(argv)

    if not parsed_args.subcommand:
        parser.print_help()
        return 0

    if parsed_args.subcommand == "setup":
        return cmd_setup(parsed_args)

    cfg = LCSConfig.resolve(root_override=parsed_args.root)
    with LCSContext(config=cfg, auto_migrate=True) as ctx:
        return parsed_args.func(ctx, parsed_args)


if __name__ == "__main__":
    sys.exit(main())

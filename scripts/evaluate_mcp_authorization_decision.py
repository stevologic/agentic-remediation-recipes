#!/usr/bin/env python3
"""Evaluate one MCP authorization decision.

The authorization conformance pack declares which MCP connectors and
candidate servers have enough resource, audience, scope, consent,
session, and audit evidence to be used by governed agent runs. This
runtime evaluator gives an MCP gateway or agent host a deterministic
allow, hold, deny, or kill-session decision before the tool call is
forwarded.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


DEFAULT_PACK = Path("data/evidence/mcp-authorization-conformance-pack.json")
VALID_DECISIONS = {
    "allow_authorized_mcp_request",
    "hold_for_authorization_evidence",
    "deny_token_passthrough",
    "deny_unbound_token",
    "deny_scope_drift",
    "kill_session_on_secret_or_signer_scope",
}


class MCPAuthorizationDecisionError(RuntimeError):
    """Raised when the pack or runtime request cannot be parsed."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise MCPAuthorizationDecisionError(f"{path} does not exist") from exc
    except json.JSONDecodeError as exc:
        raise MCPAuthorizationDecisionError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise MCPAuthorizationDecisionError(f"{path} root must be a JSON object")
    return payload


def as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def connectors_by_id(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = []
    rows.extend(as_list(pack.get("registered_connector_authorization")))
    rows.extend(as_list(pack.get("candidate_authorization")))
    return {
        str(row.get("connector_id") or row.get("candidate_id")): row
        for row in rows
        if isinstance(row, dict) and (row.get("connector_id") or row.get("candidate_id"))
    }


def connectors_by_namespace(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = []
    rows.extend(as_list(pack.get("registered_connector_authorization")))
    rows.extend(as_list(pack.get("candidate_authorization")))
    return {
        str(row.get("namespace")): row
        for row in rows
        if isinstance(row, dict) and row.get("namespace")
    }


def workflows_by_id(pack: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(row.get("workflow_id")): row
        for row in as_list(pack.get("workflow_authorization_map"))
        if isinstance(row, dict) and row.get("workflow_id")
    }


def namespace_in_workflow(workflow: dict[str, Any] | None, namespace: str) -> bool:
    if not workflow or not namespace:
        return True
    return any(
        isinstance(row, dict) and str(row.get("namespace")) == namespace
        for row in workflow.get("namespaces", []) or []
    )


def normalize_request(runtime_request: dict[str, Any]) -> dict[str, Any]:
    request = dict(runtime_request)
    for key in [
        "workflow_id",
        "agent_id",
        "run_id",
        "connector_id",
        "namespace",
        "client_id",
        "resource_indicator",
        "token_audience",
        "token_issuer",
        "token_expires_at",
        "requested_access_mode",
        "consent_record_id",
        "session_id",
        "correlation_id",
        "gateway_policy_hash",
    ]:
        request[key] = str(request.get(key) or "").strip()
    request["token_passthrough"] = as_bool(request.get("token_passthrough"))
    request["contains_secret_scope"] = as_bool(request.get("contains_secret_scope"))
    request["token_scopes"] = [str(scope).strip() for scope in as_list(request.get("token_scopes")) if str(scope).strip()]
    return request


def decision_result(
    *,
    decision: str,
    reason: str,
    pack: dict[str, Any],
    request: dict[str, Any],
    connector: dict[str, Any] | None = None,
    workflow: dict[str, Any] | None = None,
    violations: list[str] | None = None,
) -> dict[str, Any]:
    if decision not in VALID_DECISIONS:
        raise MCPAuthorizationDecisionError(f"unknown decision {decision!r}")
    return {
        "allowed": decision == "allow_authorized_mcp_request",
        "decision": decision,
        "evidence": {
            "authorization_pack_generated_at": pack.get("generated_at"),
            "canonical_resource_uri": connector.get("canonical_resource_uri") if connector else None,
            "conformance_decision": connector.get("conformance_decision") if connector else None,
            "observed_runtime_attributes": sorted(k for k, v in request.items() if v not in (None, "", [], {}, False)),
            "source_artifacts": pack.get("source_artifacts"),
        },
        "matched_connector": connector,
        "matched_workflow": workflow,
        "reason": reason,
        "request": {
            "agent_id": request.get("agent_id"),
            "client_id": request.get("client_id"),
            "connector_id": request.get("connector_id"),
            "correlation_id": request.get("correlation_id"),
            "namespace": request.get("namespace"),
            "requested_access_mode": request.get("requested_access_mode"),
            "resource_indicator": request.get("resource_indicator"),
            "run_id": request.get("run_id"),
            "session_id": request.get("session_id"),
            "token_audience": request.get("token_audience"),
            "token_issuer": request.get("token_issuer"),
            "token_passthrough": request.get("token_passthrough"),
            "token_scopes": request.get("token_scopes", []),
            "workflow_id": request.get("workflow_id"),
        },
        "violations": violations or [],
    }


def evaluate_mcp_authorization_decision(
    authorization_pack: dict[str, Any],
    runtime_request: dict[str, Any],
) -> dict[str, Any]:
    """Return a structured authorization decision for one MCP request."""
    if not isinstance(authorization_pack, dict):
        raise MCPAuthorizationDecisionError("authorization_pack must be an object")
    if not isinstance(runtime_request, dict):
        raise MCPAuthorizationDecisionError("runtime_request must be an object")

    request = normalize_request(runtime_request)
    contract = authorization_pack.get("authorization_contract", {})
    if not isinstance(contract, dict):
        contract = {}
    prohibited_terms = {str(term) for term in contract.get("prohibited_scope_terms", []) or []}

    if request["token_passthrough"]:
        return decision_result(
            decision="deny_token_passthrough",
            reason="raw user or upstream token passthrough is prohibited",
            pack=authorization_pack,
            request=request,
            violations=["token_passthrough=true"],
        )

    requested_scope_text = " ".join(request.get("token_scopes", [])).lower()
    if request["contains_secret_scope"] or any(term in requested_scope_text for term in prohibited_terms):
        return decision_result(
            decision="kill_session_on_secret_or_signer_scope",
            reason="request includes a prohibited credential, signer, deploy, publish, or live-funds scope",
            pack=authorization_pack,
            request=request,
            violations=["prohibited authorization scope requested"],
        )

    connector = None
    if request["connector_id"]:
        connector = connectors_by_id(authorization_pack).get(request["connector_id"])
    if connector is None and request["namespace"]:
        connector = connectors_by_namespace(authorization_pack).get(request["namespace"])

    workflow = workflows_by_id(authorization_pack).get(request["workflow_id"]) if request["workflow_id"] else None
    violations: list[str] = []

    if connector is None:
        violations.append("connector_id or namespace is not registered in authorization pack")
        return decision_result(
            decision="hold_for_authorization_evidence",
            reason="authorization profile is not registered",
            pack=authorization_pack,
            request=request,
            workflow=workflow,
            violations=violations,
        )

    namespace = str(connector.get("namespace") or request["namespace"])
    if request["workflow_id"] and workflow is None:
        violations.append(f"workflow_id is not registered: {request['workflow_id']}")
    if workflow and not namespace_in_workflow(workflow, namespace):
        violations.append(f"namespace {namespace!r} is not approved for workflow {request['workflow_id']!r}")

    access_modes = {str(mode) for mode in connector.get("access_modes", []) or []}
    if request["requested_access_mode"] and request["requested_access_mode"] not in access_modes:
        violations.append(
            f"requested_access_mode {request['requested_access_mode']!r} is outside connector access modes {sorted(access_modes)}"
        )
    if violations:
        return decision_result(
            decision="deny_scope_drift",
            reason="request is outside the workflow or connector authorization scope",
            pack=authorization_pack,
            request=request,
            connector=connector,
            workflow=workflow,
            violations=violations,
        )

    canonical_resource_uri = str(connector.get("canonical_resource_uri") or contract.get("canonical_mcp_resource_uri") or "")
    transport = str(connector.get("transport") or "")
    if transport != "stdio":
        if not request["resource_indicator"]:
            violations.append("resource_indicator is required for HTTP MCP authorization")
        elif canonical_resource_uri and request["resource_indicator"] != canonical_resource_uri:
            violations.append("resource_indicator does not match canonical MCP resource URI")
        if not request["token_audience"]:
            violations.append("token_audience is required for HTTP MCP authorization")
        elif canonical_resource_uri and request["token_audience"] != canonical_resource_uri:
            violations.append("token_audience does not match canonical MCP resource URI")
        if violations:
            return decision_result(
                decision="deny_unbound_token",
                reason="token is not bound to the expected MCP resource",
                pack=authorization_pack,
                request=request,
                connector=connector,
                workflow=workflow,
                violations=violations,
            )

    if str(connector.get("conformance_decision")) in {
        "hold_for_authorization_evidence",
        "hold_for_live_metadata",
        "deny_until_redesigned",
    }:
        return decision_result(
            decision="hold_for_authorization_evidence",
            reason="connector authorization profile still requires conformance evidence",
            pack=authorization_pack,
            request=request,
            connector=connector,
            workflow=workflow,
            violations=connector.get("control_gaps", []) or connector.get("metadata_evidence_required", []),
        )

    return decision_result(
        decision="allow_authorized_mcp_request",
        reason="request satisfies MCP authorization conformance policy",
        pack=authorization_pack,
        request=request,
        connector=connector,
        workflow=workflow,
    )


def request_from_args(args: argparse.Namespace) -> dict[str, Any]:
    if args.request:
        payload = load_json(args.request)
    else:
        payload = {}
    for key in [
        "workflow_id",
        "agent_id",
        "run_id",
        "connector_id",
        "namespace",
        "client_id",
        "resource_indicator",
        "token_audience",
        "token_issuer",
        "token_expires_at",
        "requested_access_mode",
        "consent_record_id",
        "session_id",
        "correlation_id",
        "gateway_policy_hash",
    ]:
        value = getattr(args, key)
        if value not in (None, ""):
            payload[key] = value
    if args.token_scope:
        payload["token_scopes"] = args.token_scope
    if args.token_passthrough:
        payload["token_passthrough"] = True
    if args.contains_secret_scope:
        payload["contains_secret_scope"] = True
    return payload


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pack", type=Path, default=DEFAULT_PACK)
    parser.add_argument("--request", type=Path)
    parser.add_argument("--workflow-id", dest="workflow_id")
    parser.add_argument("--agent-id", dest="agent_id")
    parser.add_argument("--run-id", dest="run_id")
    parser.add_argument("--connector-id", dest="connector_id")
    parser.add_argument("--namespace")
    parser.add_argument("--client-id", dest="client_id")
    parser.add_argument("--resource-indicator", dest="resource_indicator")
    parser.add_argument("--token-audience", dest="token_audience")
    parser.add_argument("--token-issuer", dest="token_issuer")
    parser.add_argument("--token-expires-at", dest="token_expires_at")
    parser.add_argument("--token-scope", action="append", default=[])
    parser.add_argument("--requested-access-mode", dest="requested_access_mode")
    parser.add_argument("--consent-record-id", dest="consent_record_id")
    parser.add_argument("--session-id", dest="session_id")
    parser.add_argument("--correlation-id", dest="correlation_id")
    parser.add_argument("--gateway-policy-hash", dest="gateway_policy_hash")
    parser.add_argument("--token-passthrough", action="store_true")
    parser.add_argument("--contains-secret-scope", action="store_true")
    parser.add_argument("--expect-decision", choices=sorted(VALID_DECISIONS))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        pack = load_json(args.pack)
        request = request_from_args(args)
        decision = evaluate_mcp_authorization_decision(pack, request)
    except (MCPAuthorizationDecisionError, json.JSONDecodeError) as exc:
        print(f"MCP authorization decision failed: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(decision, indent=2, sort_keys=True))
    if args.expect_decision and decision.get("decision") != args.expect_decision:
        print(
            f"expected decision {args.expect_decision!r}, got {decision.get('decision')!r}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

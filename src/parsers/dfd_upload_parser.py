"""
DFD Upload Parser
=================

Converts user-uploaded DFDs (PlantUML / Mermaid / JSON) into a fully-formed
``DataFlowDiagram`` pydantic object so the orchestrator can consume them
directly without re-inferring the system from a text description.

This is the fix for the bug where uploading a custom DFD was silently ignored:
the previous code flattened the upload into a string and let the LLM-driven
DFDBuilder rebuild the diagram from scratch.

Heuristics for node classification (when type is not given):
    user | client | actor | browser | external | attacker   -> ExternalEntity
    db | database | store | cache | s3 | bucket | redis     -> DataStore
                                                | log | queue
    everything else                                          -> Process
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from src.models.dfd_components import (
    AuthenticationMethod,
    DataClassification,
    DataFlow,
    DataFlowDiagram,
    DataStore,
    ExternalEntity,
    Process,
    TransportProtocol,
    TrustLevel,
)


# ---------------------------------------------------------------------------
# Heuristic classification
# ---------------------------------------------------------------------------

_ENTITY_PAT = re.compile(
    r"\b(user|users|client|clients|actor|browser|external|attacker|customer|partner)\b",
    re.IGNORECASE,
)
_STORE_PAT = re.compile(
    r"(?:\b(db|database|datastore|store|cache|s3|bucket|queue|kafka|log|logs|"
    r"filesystem|file system)\b)"
    r"|(?i:postgres|postgresql|mysql|mariadb|mongodb|mongo|sqlite|redis|"
    r"elasticsearch|dynamodb|cassandra)",
    re.IGNORECASE,
)

_PROTOCOL_LOOKUP = {
    "http": TransportProtocol.HTTP,
    "https": TransportProtocol.HTTPS,
    "ssh": TransportProtocol.SSH,
    "ftp": TransportProtocol.FTP,
    "sftp": TransportProtocol.SFTP,
    "smtp": TransportProtocol.SMTP,
    "sql": TransportProtocol.SQL,
    "websocket": TransportProtocol.WEBSOCKET,
    "ws": TransportProtocol.WEBSOCKET,
    "wss": TransportProtocol.WEBSOCKET,
    "grpc": TransportProtocol.GRPC,
    "mqtt": TransportProtocol.MQTT,
}


def _classify(name: str, explicit_type: Optional[str] = None) -> str:
    """Decide whether a node is entity, process, or store."""
    if explicit_type:
        et = explicit_type.lower()
        if et in {"entity", "external", "external_entity", "actor", "user"}:
            return "entity"
        if et in {"store", "data_store", "datastore", "db", "database"}:
            return "store"
        return "process"

    if _ENTITY_PAT.search(name):
        return "entity"
    if _STORE_PAT.search(name):
        return "store"
    return "process"


def _classify_protocol(label: Optional[str]) -> TransportProtocol:
    if not label:
        return TransportProtocol.HTTP
    lab = label.strip().lower()
    # Longer/more specific keys first so 'https' wins over 'http' and 'sftp' over 'ftp'.
    for needle in sorted(_PROTOCOL_LOOKUP, key=len, reverse=True):
        if needle in lab:
            return _PROTOCOL_LOOKUP[needle]
    return TransportProtocol.CUSTOM


def _node_carries_sensitive(name: str) -> bool:
    return bool(
        re.search(
            r"\b(auth|login|token|credential|password|pii|patient|payment|card|ssn|medical)\b",
            name,
            re.IGNORECASE,
        )
    )


# ---------------------------------------------------------------------------
# Format parsers
# ---------------------------------------------------------------------------


_MermaidEdge = Tuple[str, str, Optional[str]]   # source, dest, label
_MermaidNode = Tuple[str, Optional[str]]        # id, display label

_MERMAID_NODE = re.compile(r"^\s*([A-Za-z0-9_]+)\s*\[([^\]]+)\]\s*$")
_MERMAID_EDGE = re.compile(
    r"^\s*([A-Za-z0-9_\[\]\"' ]+?)\s*"
    r"(?:==>|-->|->)\s*"
    r"(?:\|([^|]+)\|\s*)?"
    r"([A-Za-z0-9_\[\]\"' ]+?)\s*$"
)


def parse_mermaid(content: str) -> Tuple[List[_MermaidNode], List[_MermaidEdge]]:
    """Pull out node aliases and edges from a Mermaid ``graph TD`` block."""
    nodes: Dict[str, Optional[str]] = {}
    edges: List[_MermaidEdge] = []

    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("%%") or line.lower().startswith("graph"):
            continue

        m = _MERMAID_NODE.match(line)
        if m:
            nodes.setdefault(m.group(1), m.group(2))
            continue

        m = _MERMAID_EDGE.match(line)
        if m:
            src_raw, label, dst_raw = m.group(1), m.group(2), m.group(3)
            src_id, src_lbl = _split_inline_node(src_raw)
            dst_id, dst_lbl = _split_inline_node(dst_raw)
            nodes.setdefault(src_id, src_lbl)
            nodes.setdefault(dst_id, dst_lbl)
            edges.append((src_id, dst_id, label.strip() if label else None))

    return list(nodes.items()), edges


def _split_inline_node(raw: str) -> Tuple[str, Optional[str]]:
    """Handle Mermaid edge endpoints that embed their label inline, e.g. ``A[User]``."""
    m = _MERMAID_NODE.match(raw)
    if m:
        return m.group(1), m.group(2)
    return raw.strip().strip('"').strip("'"), None


_PlantEdge = Tuple[str, str, Optional[str]]

_PLANT_EDGE = re.compile(
    r"^\s*([A-Za-z0-9_]+)\s*-+>\s*([A-Za-z0-9_]+)\s*(?::\s*(.+))?$"
)


def parse_plantuml(content: str) -> Tuple[List[Tuple[str, Optional[str]]], List[_PlantEdge]]:
    """Pull nodes + edges from a minimal PlantUML diagram."""
    nodes: Dict[str, Optional[str]] = {}
    edges: List[_PlantEdge] = []

    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("@") or line.startswith("'"):
            continue

        m = _PLANT_EDGE.match(line)
        if m:
            src, dst, label = m.group(1), m.group(2), m.group(3)
            nodes.setdefault(src, None)
            nodes.setdefault(dst, None)
            edges.append((src, dst, label.strip() if label else None))

    return list(nodes.items()), edges


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def parse_uploaded_dfd(
    fmt: str,
    content: str,
    diagram_name: str = "Uploaded DFD",
) -> DataFlowDiagram:
    """
    Convert an uploaded DFD into a real ``DataFlowDiagram``.

    Parameters
    ----------
    fmt :
        ``"mermaid"``, ``"plantuml"``, or ``"json"``. ``"auto"`` is detected
        upstream in the API layer; by the time we get here we expect a
        concrete format.
    content :
        The diagram text.
    diagram_name :
        Display name written into the DFD.

    Returns
    -------
    DataFlowDiagram with concrete pydantic nodes, real UUIDs, and
    ``DataFlow`` records that point at those UUIDs (not name strings).
    """
    fmt = (fmt or "").strip().lower()

    if fmt == "json":
        return _parse_json_format(content, diagram_name)
    if fmt == "plantuml":
        nodes, edges = parse_plantuml(content)
    elif fmt == "mermaid":
        nodes, edges = parse_mermaid(content)
    else:
        raise ValueError(f"unsupported DFD format: {fmt}")

    return _build_dfd(nodes, edges, diagram_name)


def _build_dfd(
    nodes: List[Tuple[str, Optional[str]]],
    edges: List[Tuple[str, str, Optional[str]]],
    diagram_name: str,
) -> DataFlowDiagram:
    """Materialise the parsed (nodes, edges) into a DataFlowDiagram."""
    entity_by_alias: Dict[str, ExternalEntity] = {}
    process_by_alias: Dict[str, Process] = {}
    store_by_alias: Dict[str, DataStore] = {}

    # Pass 1: classify and instantiate each node
    for alias, label in nodes:
        display = label or alias
        kind = _classify(display)

        if kind == "entity":
            entity_by_alias[alias] = ExternalEntity(
                name=display,
                description=f"External entity '{display}' (from uploaded DFD)",
                trust_level=TrustLevel.UNTRUSTED,
            )
        elif kind == "store":
            store_by_alias[alias] = DataStore(
                name=display,
                description=f"Data store '{display}' (from uploaded DFD)",
                trust_level=TrustLevel.HIGH_TRUST,
                stores_pii=_node_carries_sensitive(display),
            )
        else:
            process_by_alias[alias] = Process(
                name=display,
                description=f"Process '{display}' (from uploaded DFD)",
                trust_level=TrustLevel.MEDIUM_TRUST,
                processes_pii=_node_carries_sensitive(display),
            )

    def lookup(alias: str):
        return (
            entity_by_alias.get(alias)
            or process_by_alias.get(alias)
            or store_by_alias.get(alias)
        )

    # Pass 2: build data flows (resolved against UUIDs of pass-1 nodes)
    data_flows: List[DataFlow] = []
    for src, dst, label in edges:
        s_node = lookup(src)
        d_node = lookup(dst)
        if not s_node or not d_node:
            # Shouldn't happen because pass 1 inserted both endpoints; skip if so.
            continue

        protocol = _classify_protocol(label)
        carries_pii = _node_carries_sensitive(label or "") or _node_carries_sensitive(s_node.name)
        is_encrypted = protocol in {TransportProtocol.HTTPS, TransportProtocol.SSH,
                                    TransportProtocol.SFTP}
        data_flows.append(
            DataFlow(
                name=label or f"{s_node.name} -> {d_node.name}",
                source_id=s_node.id,
                destination_id=d_node.id,
                data_description=label or "data",
                data_classification=(
                    DataClassification.CONFIDENTIAL if carries_pii else DataClassification.INTERNAL
                ),
                carries_pii=carries_pii,
                protocol=protocol,
                isEncrypted=is_encrypted,
                authentication=AuthenticationMethod.NONE,
            )
        )

    return DataFlowDiagram(
        name=diagram_name,
        description=f"User-uploaded DFD with {len(nodes)} nodes and {len(edges)} flows.",
        external_entities=list(entity_by_alias.values()),
        processes=list(process_by_alias.values()),
        data_stores=list(store_by_alias.values()),
        data_flows=data_flows,
        trust_boundaries=[],
    )


def _parse_json_format(content: str, diagram_name: str) -> DataFlowDiagram:
    """
    Accepted JSON shape (matches what the API was already pretending to parse):

        {
          "nodes": [
            {"name": "User",        "type": "entity"},
            {"name": "API Gateway", "type": "process"},
            {"name": "PostgreSQL",  "type": "store"}
          ],
          "edges": [
            {"from": "User", "to": "API Gateway", "protocol": "HTTPS"},
            {"from": "API Gateway", "to": "PostgreSQL", "protocol": "SQL"}
          ]
        }

    ``type`` is optional; if missing we fall back to the same heuristics
    used for Mermaid/PlantUML.
    """
    data = json.loads(content)
    raw_nodes: List[Dict[str, Any]] = data.get("nodes", [])
    raw_edges: List[Dict[str, Any]] = data.get("edges", [])

    entity_by_alias: Dict[str, ExternalEntity] = {}
    process_by_alias: Dict[str, Process] = {}
    store_by_alias: Dict[str, DataStore] = {}

    for n in raw_nodes:
        name = n["name"]
        kind = _classify(name, explicit_type=n.get("type"))

        if kind == "entity":
            entity_by_alias[name] = ExternalEntity(
                name=name,
                description=n.get("description") or f"External entity '{name}'",
                trust_level=TrustLevel.UNTRUSTED,
            )
        elif kind == "store":
            store_by_alias[name] = DataStore(
                name=name,
                description=n.get("description") or f"Data store '{name}'",
                trust_level=TrustLevel.HIGH_TRUST,
                stores_pii=bool(n.get("stores_pii")) or _node_carries_sensitive(name),
                isEncrypted=bool(n.get("encrypted")),
                technology=n.get("technology"),
            )
        else:
            process_by_alias[name] = Process(
                name=name,
                description=n.get("description") or f"Process '{name}'",
                trust_level=TrustLevel.MEDIUM_TRUST,
                processes_pii=bool(n.get("processes_pii")) or _node_carries_sensitive(name),
                implementsAuthentication=bool(n.get("implements_authentication")),
                sanitizesInput=bool(n.get("sanitizes_input")),
                technology=n.get("technology"),
            )

    def lookup(name: str):
        return (
            entity_by_alias.get(name)
            or process_by_alias.get(name)
            or store_by_alias.get(name)
        )

    data_flows: List[DataFlow] = []
    for e in raw_edges:
        s = lookup(e["from"])
        d = lookup(e["to"])
        if not s or not d:
            continue
        protocol = _classify_protocol(e.get("protocol"))
        data_flows.append(
            DataFlow(
                name=e.get("label") or f"{s.name} -> {d.name}",
                source_id=s.id,
                destination_id=d.id,
                data_description=e.get("data") or e.get("label") or "data",
                data_classification=DataClassification.INTERNAL,
                carries_pii=bool(e.get("carries_pii")) or _node_carries_sensitive(e.get("label", "")),
                protocol=protocol,
                isEncrypted=bool(e.get("encrypted"))
                or protocol in {TransportProtocol.HTTPS, TransportProtocol.SSH, TransportProtocol.SFTP},
                authentication=AuthenticationMethod.NONE,
            )
        )

    return DataFlowDiagram(
        name=diagram_name,
        description=f"User-uploaded DFD (JSON) with {len(raw_nodes)} nodes and {len(raw_edges)} flows.",
        external_entities=list(entity_by_alias.values()),
        processes=list(process_by_alias.values()),
        data_stores=list(store_by_alias.values()),
        data_flows=data_flows,
        trust_boundaries=[],
    )

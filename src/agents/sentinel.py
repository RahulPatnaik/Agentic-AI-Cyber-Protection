"""
WiFi Sentinel Agent - Reasoning & Response
LLM-based threat analysis and autonomous response with Pydantic AI
"""

from pydantic_ai import Agent, RunContext
from typing import Optional, Dict, Any
import structlog

from src.models.alerts import SecurityAlert
from src.models.responses import SecurityResponse, ResponseAction, MitreAttack, FeatureImportance, ActionType
from src.dependencies.sentinel_deps import SentinelDependencies

logger = structlog.get_logger()


# Pydantic AI Agent Configuration
sentinel_agent = Agent(
    'mistral:mistral-large-latest',
    deps_type=SentinelDependencies,
    system_prompt="""You are WiFi Sentinel, an expert cybersecurity reasoning agent.

Your role:
1. Receive threat alerts from WiFi Guardian (ML detection agent)
2. Analyze threats in full network context (devices, history, policies)
3. Assess risk severity (1-10 scale)
4. Determine optimal response action (alert/isolate/block/escalate)
5. Generate explainable AI outputs for human analysts
6. Map threats to MITRE ATT&CK framework

Available tools:
- query_threat_intel: Get latest threat intelligence
- map_to_mitre: Identify MITRE ATT&CK techniques
- calculate_risk_score: Risk assessment
- generate_explanation: Create human-readable explanation
- notify_team: Send alert to security team

Response Decision Matrix:
- Critical + >95% confidence → Recommend isolate_device
- High + >90% confidence → Recommend block_mac
- Medium + >85% confidence → Recommend alert_only
- Low or <85% confidence → Recommend log_only

Safety Rules:
- Be cautious with blocking actions
- Always provide clear explanations
- Consider false positive probability
- Recommend human review for critical actions

When analyzing threats:
1. Query threat intelligence using query_threat_intel
2. Calculate comprehensive risk score
3. Map to MITRE ATT&CK framework
4. Determine appropriate response action
5. Generate clear explanation of your decision
""",
)


@sentinel_agent.tool
async def query_threat_intel(
    ctx: RunContext[SentinelDependencies],
    threat_type: str
) -> Dict[str, Any]:
    """
    Query threat intelligence feeds for latest information.

    Args:
        threat_type: Type of threat to query

    Returns:
        Threat intelligence data
    """
    threat_intel = ctx.deps.threat_intel

    if threat_type in threat_intel:
        return threat_intel[threat_type]

    return {
        'severity': 'unknown',
        'description': f'No threat intelligence available for {threat_type}'
    }


@sentinel_agent.tool
async def map_to_mitre(
    ctx: RunContext[SentinelDependencies],
    threat_type: str
) -> Optional[Dict[str, str]]:
    """
    Map threat to MITRE ATT&CK framework.

    Args:
        threat_type: Type of threat

    Returns:
        MITRE ATT&CK mapping
    """
    mitre_mappings = ctx.deps.mitre_mappings

    if threat_type in mitre_mappings:
        return mitre_mappings[threat_type]

    return None


@sentinel_agent.tool
async def calculate_risk_score(
    ctx: RunContext[SentinelDependencies],
    alert: SecurityAlert,
    threat_intel: Dict[str, Any]
) -> float:
    """
    Calculate comprehensive risk score (0.0-10.0).

    Args:
        alert: SecurityAlert instance
        threat_intel: Threat intelligence data

    Returns:
        Risk score
    """
    # Base score from ML confidence
    base_score = alert.confidence * 10.0

    # Adjust based on severity
    severity_multipliers = {
        'low': 0.5,
        'medium': 0.8,
        'high': 1.2,
        'critical': 1.5
    }
    severity_mult = severity_multipliers.get(alert.severity.value, 1.0)

    # Adjust based on threat intel severity
    intel_severity = threat_intel.get('severity', 'unknown')
    if intel_severity == 'critical':
        base_score *= 1.3
    elif intel_severity == 'high':
        base_score *= 1.2

    final_score = min(10.0, base_score * severity_mult)

    return round(final_score, 2)


@sentinel_agent.tool
async def generate_explanation(
    ctx: RunContext[SentinelDependencies],
    alert: SecurityAlert,
    risk_score: float,
    recommended_action: str
) -> str:
    """
    Generate human-readable explanation of the decision.

    Args:
        alert: SecurityAlert instance
        risk_score: Calculated risk score
        recommended_action: Recommended response action

    Returns:
        Explanation text
    """
    explanation = f"""I detected a {alert.threat_type.value} with {alert.confidence*100:.1f}% confidence.

Key Indicators:
"""

    # Add indicators
    indicators = alert.attack_indicators
    if indicators.arp_spoofing:
        explanation += "- ARP spoofing detected (device claiming to be router)\n"
    if indicators.duplicate_ip:
        explanation += "- Duplicate IP address detected\n"
    if indicators.deauth_frames:
        explanation += "- Excessive deauthentication frames\n"
    if indicators.dns_anomaly:
        explanation += "- DNS response anomalies detected\n"
    if indicators.ssid_mismatch:
        explanation += "- SSID mismatch with known MAC address\n"

    explanation += f"""
ML Analysis:
- Ensemble vote: {alert.ensemble_vote}
- Confidence: {alert.confidence*100:.1f}%
- Models used: {len(alert.ml_predictions)}

Risk Assessment:
- Risk Score: {risk_score}/10
- Severity: {alert.severity.value}

Recommended Action: {recommended_action}
Reason: Based on the high confidence and severity, immediate action is recommended to prevent potential data theft or network disruption.
"""

    return explanation


@sentinel_agent.tool
async def notify_team(
    ctx: RunContext[SentinelDependencies],
    incident: SecurityResponse
) -> Dict[str, str]:
    """
    Notify security team about incident.

    Args:
        incident: SecurityResponse instance

    Returns:
        Notification status
    """
    # For MVP, just log the notification
    logger.warning(
        "SECURITY ALERT",
        incident_id=str(incident.incident_id),
        threat_summary=incident.threat_summary,
        risk_score=incident.risk_score,
        recommended_action=incident.recommended_action.action_type.value if incident.recommended_action else None
    )

    return {
        'notified': True,
        'channel': 'console_log',
        'incident_id': str(incident.incident_id)
    }


@sentinel_agent.output_validator
async def validate_security_response(
    ctx: RunContext[SentinelDependencies],
    result: SecurityResponse
) -> SecurityResponse:
    """
    Validate SecurityResponse output.

    Args:
        result: SecurityResponse instance

    Returns:
        Validated SecurityResponse

    Raises:
        ValueError: If validation fails
    """
    # Validate risk score
    if result.risk_score < 0.0 or result.risk_score > 10.0:
        raise ValueError(f"Invalid risk_score: {result.risk_score}")

    # Validate false positive probability
    if result.false_positive_probability < 0.0 or result.false_positive_probability > 1.0:
        raise ValueError(f"Invalid false_positive_probability: {result.false_positive_probability}")

    logger.debug(
        "SecurityResponse validated",
        incident_id=str(result.incident_id),
        risk_score=result.risk_score
    )

    return result


# Main analysis function (called from message queue handler)
async def run_sentinel_analysis(
    alert: SecurityAlert,
    deps: SentinelDependencies
) -> SecurityResponse:
    """
    Main reasoning pipeline using Sentinel agent.

    Args:
        alert: SecurityAlert from Guardian
        deps: SentinelDependencies instance

    Returns:
        SecurityResponse with analysis and recommendations
    """
    try:
        # Check cache first
        cache_key = f"threat_{alert.threat_type.value}_{alert.confidence:.2f}"
        cached_analysis = deps.response_cache.get(cache_key)

        # Create prompt for agent
        prompt = f"""Analyze this security alert and determine the appropriate response:

Alert Details:
- Threat ID: {alert.threat_id}
- Threat Type: {alert.threat_type.value}
- Severity: {alert.severity.value}
- Confidence: {alert.confidence*100:.1f}%
- Source Device: {alert.source_device.mac}
- Target Device: {alert.target_device.mac if alert.target_device else 'N/A'}

Attack Indicators:
- ARP Spoofing: {alert.attack_indicators.arp_spoofing}
- Duplicate IP: {alert.attack_indicators.duplicate_ip}
- Deauth Frames: {alert.attack_indicators.deauth_frames}
- DNS Anomaly: {alert.attack_indicators.dns_anomaly}

ML Predictions:
{alert.ml_predictions}

Use the available tools to:
1. Query threat intelligence for {alert.threat_type.value}
2. Map this threat to MITRE ATT&CK framework
3. Calculate a comprehensive risk score
4. Generate a clear explanation
5. Recommend appropriate response action

Provide a comprehensive SecurityResponse with all analysis details.
"""

        # Run Sentinel agent
        result = await sentinel_agent.run(prompt, deps=deps)

        response = result.data  # SecurityResponse object

        # Cache the analysis
        if deps.config.enable_response_cache:
            deps.response_cache.set(cache_key, str(response.model_dump()))

        # Store incident
        deps.incident_storage.append(response)

        # Notify team for high-risk incidents
        if response.risk_score >= 7.0:
            await notify_team(
                RunContext(deps=deps, retry=0),
                response
            )

        logger.info(
            "Sentinel analysis complete",
            incident_id=str(response.incident_id),
            alert_id=str(alert.threat_id),
            risk_score=response.risk_score,
            recommended_action=response.recommended_action.action_type.value if response.recommended_action else None
        )

        return response

    except Exception as e:
        logger.error("Sentinel analysis failed", error=str(e), alert_id=str(alert.threat_id))
        raise

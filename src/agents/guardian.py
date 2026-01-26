"""
WiFi Guardian Agent - Detection & Analysis
Real-time ML-based threat detection with Pydantic AI
"""

from pydantic_ai import Agent, RunContext
from typing import Optional, Dict, Any
import structlog

from src.models.alerts import SecurityAlert, Device, AttackIndicators, ThreatType, SeverityLevel
from src.models.network import PacketFeatures
from src.dependencies.guardian_deps import GuardianDependencies

logger = structlog.get_logger()


# Pydantic AI Agent Configuration
guardian_agent = Agent(
    'mistral:mistral-large-latest',
    deps_type=GuardianDependencies,
    system_prompt="""You are WiFi Guardian, a real-time threat detection agent.

Your role:
1. Analyze network packets using ML models for threat detection
2. Extract threat indicators from suspicious activity
3. Determine severity levels (low/medium/high/critical)
4. Escalate high-severity threats to WiFi Sentinel for reasoning
5. Log all detections with confidence scores

Available tools:
- extract_features: Convert packets to ML feature vectors
- predict_threat: Run ML ensemble for classification
- lookup_threat_db: Query historical threat database
- escalate_to_sentinel: Hand off to Agent 2 for LLM analysis

Guidelines:
- Detection latency must be <100ms
- Only escalate threats with confidence >85%
- Always include packet evidence and ML model outputs
- Use threat_type from ML prediction if confidence >90%

When analyzing packets:
1. Extract features using extract_features tool
2. Run ML prediction using predict_threat tool
3. If malicious and high confidence, create SecurityAlert
4. If critical/high severity and confidence >85%, escalate to Sentinel
""",
)


@guardian_agent.tool
async def extract_features(
    ctx: RunContext[GuardianDependencies],
    packet_data: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Extract ML features from raw packet data.

    Args:
        packet_data: Raw packet dictionary

    Returns:
        Extracted features as dictionary
    """
    try:
        extractor = ctx.deps.feature_extractor
        features = await extractor.extract(packet_data)

        return {
            'src_mac': features.src_mac,
            'dst_mac': features.dst_mac,
            'packet_size': features.packet_size,
            'packet_rate': features.packet_rate,
            'byte_rate': features.byte_rate,
            'unique_dst_ips': features.unique_dst_ips,
            'rssi': features.rssi,
            'protocol': features.protocol
        }
    except Exception as e:
        logger.error("Feature extraction failed", error=str(e))
        return {'error': str(e)}


@guardian_agent.tool
async def predict_threat(
    ctx: RunContext[GuardianDependencies],
    packet_data: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Run ML ensemble prediction on packet.

    Args:
        packet_data: Raw packet dictionary

    Returns:
        ML prediction with threat type and confidence
    """
    try:
        # Extract features first
        extractor = ctx.deps.feature_extractor
        features = await extractor.extract(packet_data)

        # Run ML prediction
        ml_engine = ctx.deps.ml_ensemble
        prediction = await ml_engine.predict(features)

        return {
            'prediction': prediction.prediction,
            'confidence': prediction.confidence,
            'model_name': prediction.model_name,
            'anomaly_score': prediction.anomaly_score,
            'is_malicious': prediction.prediction != 'benign'
        }
    except Exception as e:
        logger.error("Prediction failed", error=str(e))
        return {'error': str(e), 'prediction': 'benign', 'confidence': 0.5}


@guardian_agent.tool
async def lookup_threat_db(
    ctx: RunContext[GuardianDependencies],
    indicator: str,
    indicator_type: str
) -> Optional[Dict[str, Any]]:
    """
    Query threat intelligence database for known indicators.

    Args:
        indicator: The indicator value (MAC, IP, SSID, etc.)
        indicator_type: Type of indicator ('mac', 'ip', 'ssid')

    Returns:
        Threat information if found, None otherwise
    """
    threat_db = ctx.deps.threat_database

    if indicator_type == 'mac' and indicator in threat_db.get('blacklisted_macs', set()):
        return {
            'found': True,
            'threat_level': 'high',
            'reason': 'Blacklisted MAC address'
        }

    if indicator_type == 'ssid' and indicator in threat_db.get('malicious_ssids', set()):
        return {
            'found': True,
            'threat_level': 'high',
            'reason': 'Known malicious SSID'
        }

    return None


@guardian_agent.tool
async def escalate_to_sentinel(
    ctx: RunContext[GuardianDependencies],
    alert: SecurityAlert
) -> Dict[str, str]:
    """
    Escalate high-severity threat to WiFi Sentinel agent.

    Args:
        alert: SecurityAlert to escalate

    Returns:
        Escalation status
    """
    try:
        message_queue = ctx.deps.message_queue

        # Determine priority based on severity
        priority_map = {
            'critical': 9,
            'high': 7,
            'medium': 5,
            'low': 3
        }
        priority = priority_map.get(alert.severity.value, 5)

        # Publish to sentinel queue
        message_id = await message_queue.publish(
            queue='sentinel_analysis',
            message=alert.model_dump(mode='json'),
            priority=priority
        )

        logger.info(
            "Alert escalated to Sentinel",
            threat_id=str(alert.threat_id),
            severity=alert.severity.value,
            message_id=message_id
        )

        return {
            'escalated': True,
            'message_id': message_id,
            'queue': 'sentinel_analysis'
        }

    except Exception as e:
        logger.error("Escalation failed", error=str(e))
        return {'escalated': False, 'error': str(e)}


@guardian_agent.output_validator
async def validate_security_alert(
    ctx: RunContext[GuardianDependencies],
    result: SecurityAlert
) -> SecurityAlert:
    """
    Validate SecurityAlert output before returning.

    Args:
        result: SecurityAlert instance

    Returns:
        Validated SecurityAlert

    Raises:
        ValueError: If validation fails
    """
    # Validate confidence score
    if result.confidence < 0.0 or result.confidence > 1.0:
        raise ValueError(f"Invalid confidence score: {result.confidence}")

    # Validate severity
    if result.severity not in list(SeverityLevel):
        raise ValueError(f"Invalid severity: {result.severity}")

    # Validate threat type
    if result.threat_type not in list(ThreatType):
        raise ValueError(f"Invalid threat_type: {result.threat_type}")

    logger.debug(
        "SecurityAlert validated",
        threat_id=str(result.threat_id),
        threat_type=result.threat_type.value,
        confidence=result.confidence
    )

    return result


# Main detection function (called from orchestrator)
async def run_guardian_detection(
    packet_data,  # Can be Dict or PacketFeatures
    deps: GuardianDependencies
) -> Optional[SecurityAlert]:
    """
    Main detection pipeline using Guardian agent.

    Args:
        packet_data: Raw packet dictionary or PacketFeatures instance
        deps: GuardianDependencies instance

    Returns:
        SecurityAlert if threat detected, None otherwise
    """
    try:
        # Convert PacketFeatures to dict if needed
        if isinstance(packet_data, PacketFeatures):
            packet_dict = packet_data.model_dump()
        else:
            packet_dict = packet_data

        # Create prompt for agent
        prompt = f"""Analyze this network packet for security threats:

Packet Data:
- Source MAC: {packet_dict.get('src_mac', 'unknown')}
- Destination MAC: {packet_dict.get('dst_mac', 'unknown')}
- Size: {packet_dict.get('packet_size', 0)} bytes
- Protocol: {packet_dict.get('protocol', 'unknown')}
- Frame Type: {packet_dict.get('frame_type', 'unknown')}

Use the available tools to:
1. Extract features from this packet
2. Run ML prediction to detect threats
3. If threat detected with high confidence, create a SecurityAlert
4. Include all relevant indicators and ML predictions

Determine if this packet is malicious and what type of threat it represents.
"""

        # Run Guardian agent
        result = await guardian_agent.run(prompt, deps=deps)

        alert = result.data  # SecurityAlert object

        # Auto-escalate high-severity threats
        if alert and alert.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]:
            if alert.confidence > deps.config.ml_confidence_threshold:
                alert.escalated_to_sentinel = True
                await escalate_to_sentinel(
                    RunContext(deps=deps, retry=0),
                    alert
                )

        return alert

    except Exception as e:
        logger.error("Guardian detection failed", error=str(e), packet_data=packet_data)
        return None

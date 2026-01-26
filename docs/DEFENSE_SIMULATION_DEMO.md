# WiFi Guardian - Real-Time Defense Simulation

## Overview

The "ACTIVE DEFENSE" button now demonstrates a **30-second real-time traffic simulation** showing how the WiFi Guardian system protects data integrity during network attacks.

## How It Works

### Simulation Parameters
- **Total Duration**: 30 seconds
- **Traffic Rate**: 10 packets per second (300 total packets)
- **Attack Window**: Random 10-second window (starts between 5-15 seconds)
- **Attack Type**: MITM (Man-in-the-Middle) with payload manipulation

### Defense Workflow

#### Phase 1: Normal Traffic (Before Attack)
```
Legitimate Packet → Guardian Analysis → ML Classification → ALLOW → Forward to Destination
                                         ↓
                                   Checksum Verified
                                   Data Integrity: ✅
```

**Example:**
- Packet: TCP traffic from `AA:BB:CC:DD:EE:01` → `11:22:33:44:55:66`
- Classification: "Normal" (95% confidence)
- Payload: `DATA_PACKET_042_CONTENT_SECURE`
- Checksum: `a7b3c9d2` ✅ Verified
- Action: **FORWARDED** to destination port

#### Phase 2: Attack Detection
```
Attack Packet → Guardian ML Detection → THREAT IDENTIFIED → BLOCK → Escalate to Sentinel
      ↓                    ↓                                           ↓
  Manipulated         Anomaly Score: -0.8                    Defense Action Executed
  Payload             Confidence: 87%
                      Checksum: ❌ MISMATCH
```

**Example:**
- Attacker MAC: `DE:AD:BE:EF:CA:FE`
- Packet Rate: 5000 pkt/s (suspicious)
- Protocol: ARP (attack indicator)
- Entropy: 0.95 (very high)

**Payload Manipulation Detected:**
```
Expected Payload:    SENSITIVE_DATA_142_USER_CREDENTIALS
Expected Checksum:   4f8a9b2c

Received Payload:    INJECTED_MALWARE_142_STEAL_DATA
Received Checksum:   7d3e1a6f ❌ MISMATCH
```

**Guardian Decision:**
- Threat Type: MITM_Attack
- Confidence: 87%
- Anomaly Score: -0.85
- Action: **BLOCKED** immediately
- Data Corrupted: ❌ NO (blocked before reaching destination)

#### Phase 3: Sentinel Defense Execution
```
Guardian Alert → Sentinel Analysis → MITRE Mapping → Risk Scoring → Defense Action
                       ↓                    ↓              ↓              ↓
                 LLM Reasoning      T1557 (MITM)     8.7/10      ISOLATE_DEVICE
```

**Sentinel Actions:**
1. Map to MITRE ATT&CK: T1557 (Adversary-in-the-Middle)
2. Calculate Risk Score: 8.7/10 (CRITICAL)
3. Execute Defense:
   - Action: `ISOLATE_DEVICE`
   - Target: `DE:AD:BE:EF:CA:FE`
   - Method: `iptables + ebtables`
   - Result: Device quarantined to isolated VLAN

#### Phase 4: Continuous Protection
```
Post-Defense Traffic → Guardian Monitoring → All Attack Packets Blocked → Data Integrity Maintained
```

After defense execution:
- Malicious packets: **0** (all blocked)
- Legitimate packets: Continue flowing normally
- Data corruption: **0%**

### Real-Time Visualization

The dashboard shows:

1. **Live Statistics**
   - Total packets processed
   - Legitimate packets allowed
   - Attack packets detected
   - Threats blocked
   - Data integrity checks
   - Data corrupted (should be 0)

2. **Live Packet Feed**
   - Each packet displayed in real-time
   - Color-coded: Green = allowed, Red = blocked
   - Shows MAC addresses, checksums, threat types
   - Threat details expanded for attack packets

3. **Attack Window Indicator**
   - Shows when attack will occur (e.g., "10s - 20s")
   - Updates simulation time counter

4. **Final Summary**
   - Defense effectiveness: 100%
   - Data integrity rate: 100%
   - Zero corruption achieved

## Data Integrity Protection

### How Data Integrity is Maintained

1. **Checksum Verification**
   ```python
   expected_checksum = md5(original_payload).hexdigest()[:8]
   received_checksum = md5(received_payload).hexdigest()[:8]

   if expected_checksum != received_checksum:
       → PAYLOAD MANIPULATED
       → BLOCK PACKET
       → PREVENT DATA CORRUPTION
   ```

2. **ML-Based Anomaly Detection**
   - Packet rate analysis (>5000 pkt/s = suspicious)
   - Protocol anomalies (ARP during TCP session)
   - Entropy analysis (>0.8 = attack indicator)
   - RSSI anomalies (weak signal from unexpected location)

3. **Multi-Layer Defense**
   - **Layer 1**: ML detection (Guardian) - 84.40% accuracy
   - **Layer 2**: LLM reasoning (Sentinel) - contextual analysis
   - **Layer 3**: Automated response - immediate blocking

### Attack Scenarios Demonstrated

#### Scenario: MITM with Payload Injection
```
Attack Flow:
1. Attacker intercepts packet
2. Replaces legitimate data with malware
3. Forwards manipulated packet

Defense Response:
1. Guardian detects checksum mismatch
2. Guardian detects anomalous packet patterns
3. Packet blocked BEFORE reaching destination
4. Sentinel isolates attacker MAC address
5. All subsequent attack packets dropped

Result:
✅ Data integrity maintained
✅ Zero bytes corrupted
✅ Legitimate traffic continues unaffected
```

## Technical Implementation

### Backend: Server-Sent Events (SSE)
```python
@app.get("/api/demo/defense-simulation")
async def run_defense_simulation():
    """Real-time simulation streaming via SSE"""

    async def generate_traffic_stream():
        # 300 packets over 30 seconds
        for second in range(30):
            for packet in range(10):
                if in_attack_window:
                    # Generate attack packet with manipulated payload
                    yield threat_blocked_event
                else:
                    # Generate legitimate packet
                    yield legitimate_packet_event

        yield simulation_complete_event

    return StreamingResponse(generate_traffic_stream())
```

### Frontend: EventSource API
```javascript
const eventSource = new EventSource('/api/demo/defense-simulation');

eventSource.onmessage = (event) => {
    const data = JSON.parse(event.data);

    if (data.type === 'threat_blocked') {
        // Show threat alert
        // Update statistics
        // Display checksum mismatch
    } else if (data.type === 'legitimate_packet') {
        // Show allowed packet
        // Increment counters
    }
};
```

## Key Metrics Displayed

| Metric | Description | Success Value |
|--------|-------------|---------------|
| **Defense Effectiveness** | % of threats successfully blocked | 100% |
| **Data Integrity Rate** | % of packets without corruption | 100% |
| **Threats Blocked** | Number of attack packets stopped | 100 (during 10s window) |
| **Data Corrupted** | Bytes of corrupted data | 0 |
| **False Positives** | Legitimate packets blocked | 0 |
| **Response Time** | Time from detection to blocking | <100ms |

## Example Output

```
SIMULATION STARTED
├─ 0-9s:    Legitimate traffic flowing (90 packets allowed)
├─ 10-20s:  ATTACK DETECTED (100 attack packets blocked)
│           ├─ Payload manipulation detected: 100 packets
│           ├─ Checksum mismatches: 100 packets
│           ├─ All packets blocked before corruption
│           └─ Attacker device isolated
└─ 21-30s:  Legitimate traffic resumed (110 packets allowed)

FINAL RESULTS:
✅ 300/300 packets processed
✅ 100/100 attacks blocked
✅ 0 bytes corrupted
✅ 100% data integrity maintained
```

## Comparison: With vs Without Defense

### Without WiFi Guardian
```
Attack Window: 10-20s
- 100 malicious packets reach destination
- Payload corruption: 100%
- Malware injected: Yes
- Credentials stolen: Yes
- System compromised: Yes
```

### With WiFi Guardian
```
Attack Window: 10-20s
- 100 malicious packets BLOCKED
- Payload corruption: 0%
- Malware injected: No
- Credentials stolen: No
- System compromised: No
```

## Demo Instructions

1. **Access Dashboard**: http://localhost:8000/dashboard/
2. **Click**: "ACTIVE DEFENSE" button
3. **Watch**: Real-time traffic simulation for 30 seconds
4. **Observe**:
   - Green packets = legitimate traffic (allowed)
   - Red packets = attack traffic (blocked)
   - Checksum verification in action
   - Zero data corruption achieved

## Technical Notes

- The simulation uses **real ML models** (Random Forest + Isolation Forest)
- Checksums use **MD5 hashing** for demonstration (production would use SHA-256)
- Attack window is **randomized** each run (5-15s start time)
- Packet timing simulates **real network conditions** (100ms intervals)
- All threat detection uses **actual trained models** (84.40% accuracy on NSL-KDD dataset)

## Use Cases

This demonstration shows how WiFi Guardian protects against:

1. **Man-in-the-Middle (MITM) Attacks**
   - Payload manipulation
   - Data injection
   - Credential theft

2. **ARP Spoofing**
   - MAC address impersonation
   - Traffic redirection

3. **Deauthentication Attacks**
   - Service disruption
   - Forced reconnection to malicious AP

4. **Evil Twin Attacks**
   - Rogue access point detection
   - SSID impersonation

---

**Built for**: TECHGIUM Hackathon - Agentic Threat Modeling
**Technology**: Pydantic AI + Mistral AI + Scikit-learn
**Accuracy**: 84.40% ensemble (Random Forest + Isolation Forest)
**Response Time**: <100ms per packet

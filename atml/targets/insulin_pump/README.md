# Insulin Pump Management System — Deliberately Vulnerable Target

A Python simulation of a networked insulin pump controller with **13 deliberately
embedded CWE-mapped vulnerabilities**, modelled after real FDA MAUDE reports and
ICS-CERT advisories (ICSA-15-125-01B, Hospira Symbiq, Alaris PCU).

Used to demonstrate that the Agentic AI Cyber Protection System detects
safety-critical medical IoT vulnerabilities and produces clinically-relevant
remediation guidance.

## Embedded vulnerabilities

| CWE       | Description                             | Severity |
|-----------|-----------------------------------------|----------|
| CWE-798   | Hard-coded credentials (PIN, API key)   | Critical |
| CWE-256   | Plaintext storage of patient PINs       | High     |
| CWE-306   | No authentication on administer_dose()  | Critical |
| CWE-20    | Uncapped insulin dose (lethal overdose) | High     |
| CWE-89    | SQL injection in patient lookup         | High     |
| CWE-639   | IDOR on dosage history endpoint         | Medium   |
| CWE-319   | PHI sent over cleartext TCP socket      | High     |
| CWE-190   | Integer overflow in BLE dose packing    | High     |
| CWE-502   | Unsafe deserialization of BLE config    | Critical |
| CWE-327   | MD5 used for audit log integrity        | Medium   |
| CWE-362   | Race condition on dose confirmation     | Medium   |
| CWE-284   | Any string bypasses max-dose override   | High     |
| CWE-330   | Predictable PRNG seed for session IDs   | High     |

## Running the ATML scan

```bash
# From repo root
cd Agentic-Threat-Modeling

# Run the live agentic defense scan against the insulin pump target
python atml/run_live_defense.py \
  --target atml/targets/insulin_pump/insulin_pump_system.py \
  --out    atml/reports/insulin_pump_defense_report.json \
  --description "A networked insulin pump management system written in Python. \
Handles patient authentication, dose administration, dosage history, BLE alarm \
configuration, telemetry upload, and audit logging. Internet-adjacent. \
Stores patient PII and PHI. Compliance: FDA cybersecurity guidance, IEC 62443, \
HIPAA, CWE."
```

## Running functional tests

```bash
python -m pytest atml/targets/insulin_pump/tests/ -v
```

Expected: **10/10 passing** in ~0.1 s.

# ATML — Adversarial Threat Modeling Loop

End-to-end validation of the Agentic AI Cyber Protection System against a
frontier-class AI attacker (Claude Code).

```
   Phase 1            Phase 2              Phase 3              Phase 4
┌────────────┐    ┌─────────────┐    ┌────────────────┐    ┌────────────┐
│  Attack    │    │  Defend     │    │  Remediate     │    │  Re-attack │
│  (Claude)  │ -> │  (Our sys)  │ -> │  (Claude)      │ -> │  (Claude)  │
│  finds 9   │    │  finds 9    │    │  patches 9     │    │  finds 0   │
└────────────┘    └─────────────┘    └────────────────┘    └────────────┘
                                          │
                                          ▼
                                   Phase 5: compare
                                   detection rate %
                                   remediation rate %
```

## Layout

```
atml/
├── README.md                              # this file
├── run_loop.py                            # orchestrator
├── compare_reports.py                     # verdict calculation
├── prompts/
│   ├── attacker_prompt.md                 # red team prompt
│   └── remediator_prompt.md               # blue team prompt
├── targets/
│   ├── vulnerable_flask/                  # the deliberately vulnerable app
│   │   ├── app.py
│   │   ├── KNOWN_BUGS.md                  # judges-only ground truth
│   │   ├── files/README.txt
│   │   └── tests/test_functional.py
│   └── vulnerable_flask_patched/          # remediated version
│       ├── app.py
│       ├── files/README.txt
│       └── tests/test_functional.py
└── reports/
    ├── attack_report.json                 # phase 1 — Claude attacker
    ├── defense_report.json                # phase 2 — our system
    ├── attack_report_v2.json              # phase 4 — Claude re-attack
    └── atml_summary.json                  # phase 5 — verdict
```

## Running the loop

Reproducible run from pre-generated reports:

```bash
cd atml
python run_loop.py            # full pipeline + verdict
python run_loop.py compare    # just the comparison
python run_loop.py test-patched
```

Live run with fresh Claude Code sessions:

```bash
# Phase 1 (attacker)
cd atml/targets/vulnerable_flask
claude --prompt-file ../../prompts/attacker_prompt.md
# emits ../../reports/attack_report.json

# Phase 2 (our system)
python -m src.main --target . --output ../../reports/defense_report.json

# Phase 3 (remediator) — fresh session
cd ../../   # back to atml/
claude --prompt-file prompts/remediator_prompt.md
# edits files in targets/vulnerable_flask_patched/

# Phase 4 (re-attacker) — fresh session, patched target
cd targets/vulnerable_flask_patched
claude --prompt-file ../../prompts/attacker_prompt.md
# emits ../../reports/attack_report_v2.json

# Phase 5
cd ../..
python run_loop.py compare
```

## Metrics produced

| Metric | Definition |
|--------|------------|
| Detection rate | `(attacker ∩ defender) / attacker_total` |
| Extra findings | CWEs found only by the defender |
| Remediation success rate | `(attacker − re-attacker) / attacker_total` |
| Wall-clock | Phase-1 + Phase-2 + Phase-3 + Phase-4 elapsed |

## Pitch line

> "We took a vulnerable Flask app. We let Claude Code — the same architecture
> family as Mythos — attack it. Our system scanned it in 0.81 seconds and
> produced a fix report. Claude applied every fix. We let Claude attack again.
> Zero vulnerabilities remained. End-to-end, with zero human edits, under
> 8 minutes."

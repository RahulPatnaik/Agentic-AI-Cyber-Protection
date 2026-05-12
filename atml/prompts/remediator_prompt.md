# Remediator Prompt (Blue Team)

**Run this in a fresh Claude Code session after the defensive scan completes.**

---

You are a senior security engineer. The file `atml/reports/defense_report.json`
contains a list of vulnerabilities found in `atml/targets/vulnerable_flask/`,
each with a suggested fix.

For every vulnerability:
1. Apply the recommended fix to the source code in-place.
2. Use safe, idiomatic Python (parameterised queries, `secrets` module,
   `subprocess.run` with `shell=False`, MarkupSafe escaping, bcrypt, etc.).
3. Preserve all existing public routes and their input/output contracts —
   the functional test suite at `atml/targets/vulnerable_flask/tests/`
   must still pass.
4. Do **not** introduce new dependencies beyond `bcrypt` and `markupsafe`
   if needed.

When done:
- Run `pytest atml/targets/vulnerable_flask/tests/` and confirm all tests pass.
- Emit `atml/reports/remediation_log.json` with each fix applied
  `{cwe_id, file, line_before, line_after, summary}`.

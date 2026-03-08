"""
GitHub Integration for Agentic Threat Modeling System

Features:
1. GitHub Actions workflow for PR threat analysis
2. GitHub Issues creation from vulnerabilities
3. GitHub Security Advisories integration
4. Automated comments on PRs with threat analysis
"""

import os
import aiohttp
import structlog
from typing import List, Optional, Dict
from datetime import datetime

from src.models.threats import ThreatModel, Vulnerability

logger = structlog.get_logger()


class GitHubIntegration:
    """
    GitHub integration for automated security threat analysis
    """

    def __init__(self, github_token: Optional[str] = None):
        """
        Initialize GitHub integration

        Args:
            github_token: GitHub Personal Access Token (or from env: GITHUB_TOKEN)
        """
        self.github_token = github_token or os.getenv("GITHUB_TOKEN")
        self.base_url = "https://api.github.com"
        self.logger = structlog.get_logger().bind(integration="github")

    async def create_issue_from_vulnerability(
        self,
        repo_owner: str,
        repo_name: str,
        vulnerability: Vulnerability
    ) -> Optional[str]:
        """
        Create a GitHub issue from a vulnerability

        Args:
            repo_owner: Repository owner (username or org)
            repo_name: Repository name
            vulnerability: Vulnerability to report

        Returns:
            Issue URL if created successfully, None otherwise
        """
        if not self.github_token:
            self.logger.warning("GitHub token not configured, cannot create issue")
            return None

        # Build issue title and body
        title = f"[Security] {vulnerability.title}"

        body = f"""## Security Vulnerability Detected

**Severity:** {vulnerability.severity.value.upper()} (CVSS: {vulnerability.cvss_score})
**CWE:** {vulnerability.cwe_id} - {vulnerability.cwe_name}
**OWASP Category:** {vulnerability.owasp_category.value if vulnerability.owasp_category else 'N/A'}

### Description
{vulnerability.description}

### Impact
{vulnerability.impact}

### Attack Vector
{vulnerability.attack_vector}

### Affected Component
{vulnerability.affected_component}

### Recommendations
{vulnerability.recommendation}

### Additional Details
- **Likelihood:** {vulnerability.likelihood}
- **Risk Score:** {vulnerability.risk_score}
- **Exploitability:** {vulnerability.exploitability}

---
Generated with [Agentic Threat Modeling](https://github.com/yourusername/agentic-threat-modeling)
"""

        # Add CVE data if available
        if vulnerability.metadata and 'related_cves' in vulnerability.metadata:
            cves = vulnerability.metadata['related_cves']
            if cves:
                body += "\n\n### Related CVEs\n"
                for cve in cves[:5]:  # Top 5 CVEs
                    body += f"- [{cve['cve_id']}](https://nvd.nist.gov/vuln/detail/{cve['cve_id']}) - CVSS: {cve.get('cvss_score', 'N/A')}\n"

        # Determine labels based on severity
        labels = ["security", vulnerability.severity.value]
        if vulnerability.owasp_category:
            labels.append("owasp-top-10")

        headers = {
            "Authorization": f"Bearer {self.github_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }

        payload = {
            "title": title,
            "body": body,
            "labels": labels
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/repos/{repo_owner}/{repo_name}/issues",
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 201:
                        data = await response.json()
                        issue_url = data.get("html_url")
                        self.logger.info(
                            "Created GitHub issue",
                            issue_url=issue_url,
                            vulnerability=vulnerability.title
                        )
                        return issue_url
                    else:
                        error_text = await response.text()
                        self.logger.error(
                            "Failed to create GitHub issue",
                            status=response.status,
                            error=error_text
                        )
                        return None

        except Exception as e:
            self.logger.error("GitHub API error", error=str(e))
            return None

    async def comment_on_pr(
        self,
        repo_owner: str,
        repo_name: str,
        pr_number: int,
        threat_model: ThreatModel
    ) -> bool:
        """
        Add a threat analysis comment to a Pull Request

        Args:
            repo_owner: Repository owner
            repo_name: Repository name
            pr_number: Pull request number
            threat_model: Threat model analysis results

        Returns:
            True if comment was added successfully
        """
        if not self.github_token:
            self.logger.warning("GitHub token not configured, cannot comment on PR")
            return False

        # Build comment body
        comment = self._build_pr_comment(threat_model)

        headers = {
            "Authorization": f"Bearer {self.github_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }

        payload = {"body": comment}

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/repos/{repo_owner}/{repo_name}/issues/{pr_number}/comments",
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 201:
                        self.logger.info("Added threat analysis comment to PR", pr_number=pr_number)
                        return True
                    else:
                        error_text = await response.text()
                        self.logger.error("Failed to comment on PR", status=response.status, error=error_text)
                        return False

        except Exception as e:
            self.logger.error("GitHub API error", error=str(e))
            return False

    def _build_pr_comment(self, threat_model: ThreatModel) -> str:
        """Build formatted comment for PR"""

        # Calculate severity distribution
        severity_counts = {}
        for vuln in threat_model.top_vulnerabilities:
            sev = vuln.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        comment = f"""## Threat Modeling Analysis Complete

**Analysis Duration:** {threat_model.analysis_duration_seconds:.2f}s
**Confidence Score:** {threat_model.confidence_score:.0%}
**Total Vulnerabilities:** {len(threat_model.vulnerabilities)}
**Critical Issues:** {len(threat_model.top_vulnerabilities)}

### Severity Distribution
"""

        for severity in ['critical', 'high', 'medium', 'low']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                comment += f"- **{severity.upper()}**: {count}\n"

        comment += "\n### Top Vulnerabilities\n\n"

        for i, vuln in enumerate(threat_model.top_vulnerabilities[:5], 1):
            comment += f"{i}. **{vuln.title}**\n"
            comment += f"   - **Severity:** {vuln.severity.value.upper()} (CVSS: {vuln.cvss_score})\n"
            comment += f"   - **CWE:** {vuln.cwe_id}\n"
            comment += f"   - **Impact:** {vuln.impact[:100]}...\n"
            comment += f"   - **Recommendation:** {vuln.recommendation[:150]}...\n\n"

        comment += "\n### Attack Paths Identified\n\n"
        for i, path in enumerate(threat_model.critical_paths[:3], 1):
            comment += f"{i}. **{path.name}**\n"
            comment += f"   - Probability: {path.probability:.0%}\n"
            comment += f"   - Damage: {path.potential_damage.value}\n"
            comment += f"   - Steps: {len(path.intermediate_steps)}\n\n"

        comment += f"\n### Agent Analyses\n\n"
        for agent_name, analysis in threat_model.agent_analyses.items():
            comment += f"- **{agent_name}:** {analysis[:100]}...\n"

        comment += f"\n---\nGenerated with [Agentic Threat Modeling](https://github.com/yourusername/agentic-threat-modeling) | Analysis ID: {datetime.now().strftime('%Y%m%d-%H%M%S')}\n"

        return comment

    async def create_security_advisory(
        self,
        repo_owner: str,
        repo_name: str,
        vulnerability: Vulnerability
    ) -> Optional[str]:
        """
        Create a GitHub Security Advisory

        Args:
            repo_owner: Repository owner
            repo_name: Repository name
            vulnerability: Vulnerability to report

        Returns:
            Advisory URL if created successfully
        """
        if not self.github_token:
            self.logger.warning("GitHub token not configured, cannot create security advisory")
            return None

        # Map severity to GitHub severity levels
        severity_map = {
            'critical': 'critical',
            'high': 'high',
            'medium': 'moderate',
            'low': 'low'
        }

        headers = {
            "Authorization": f"Bearer {self.github_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }

        payload = {
            "summary": vulnerability.title,
            "description": f"{vulnerability.description}\n\n## Impact\n{vulnerability.impact}\n\n## Remediation\n{vulnerability.recommendation}",
            "severity": severity_map.get(vulnerability.severity.value, 'moderate'),
            "cwe_ids": [vulnerability.cwe_id.replace('CWE-', '')] if vulnerability.cwe_id else [],
            "cvss_vector_string": f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # Placeholder
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/repos/{repo_owner}/{repo_name}/security-advisories",
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 201:
                        data = await response.json()
                        advisory_url = data.get("html_url")
                        self.logger.info("Created security advisory", advisory_url=advisory_url)
                        return advisory_url
                    else:
                        error_text = await response.text()
                        self.logger.error("Failed to create security advisory", status=response.status, error=error_text)
                        return None

        except Exception as e:
            self.logger.error("GitHub API error", error=str(e))
            return None

    async def create_fix_pr(
        self,
        repo_owner: str,
        repo_name: str,
        vulnerabilities: List[Vulnerability],
        base_branch: str = "main"
    ) -> Optional[str]:
        """
        Create a Pull Request with automated fixes for vulnerabilities

        Args:
            repo_owner: Repository owner
            repo_name: Repository name
            vulnerabilities: List of vulnerabilities to fix
            base_branch: Base branch to create PR against

        Returns:
            PR URL if created successfully
        """
        if not self.github_token:
            self.logger.warning("GitHub token not configured, cannot create PR")
            return None

        try:
            # Use a consistent branch name instead of timestamped
            branch_name = "automated-security-fixes"

            headers = {
                "Authorization": f"Bearer {self.github_token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28"
            }

            async with aiohttp.ClientSession() as session:
                # Get the default branch's latest commit SHA
                async with session.get(
                    f"{self.base_url}/repos/{repo_owner}/{repo_name}/git/ref/heads/{base_branch}",
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status != 200:
                        self.logger.error("Failed to get base branch", status=response.status)
                        return None
                    ref_data = await response.json()
                    base_sha = ref_data["object"]["sha"]

                # Check if branch already exists
                branch_exists = False
                async with session.get(
                    f"{self.base_url}/repos/{repo_owner}/{repo_name}/git/ref/heads/{branch_name}",
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 200:
                        branch_exists = True
                        self.logger.info("Branch already exists, will update it", branch=branch_name)

                if not branch_exists:
                    # Create new branch
                    async with session.post(
                        f"{self.base_url}/repos/{repo_owner}/{repo_name}/git/refs",
                        headers=headers,
                        json={
                            "ref": f"refs/heads/{branch_name}",
                            "sha": base_sha
                        },
                        timeout=aiohttp.ClientTimeout(total=30)
                    ) as response:
                        if response.status != 201:
                            error_text = await response.text()
                            self.logger.error("Failed to create branch", status=response.status, error=error_text)
                            return None
                else:
                    # Update existing branch to latest base
                    async with session.patch(
                        f"{self.base_url}/repos/{repo_owner}/{repo_name}/git/refs/heads/{branch_name}",
                        headers=headers,
                        json={
                            "sha": base_sha,
                            "force": True
                        },
                        timeout=aiohttp.ClientTimeout(total=30)
                    ) as response:
                        if response.status not in [200, 201]:
                            error_text = await response.text()
                            self.logger.warning("Failed to update branch", error=error_text)

                # Generate fix files for each vulnerability
                fixes_applied = []
                for vuln in vulnerabilities[:5]:  # Fix top 5 vulnerabilities
                    fix_content = self._generate_fix_code(vuln)
                    if fix_content:
                        fixes_applied.append({
                            "vulnerability": vuln.title,
                            "fix": fix_content
                        })

                # Create a summary file for the fixes
                fix_summary = self._build_fix_summary(vulnerabilities[:5], fixes_applied)

                # Commit the summary file to the new branch
                async with session.put(
                    f"{self.base_url}/repos/{repo_owner}/{repo_name}/contents/SECURITY_FIXES.md",
                    headers=headers,
                    json={
                        "message": "Add automated security fixes summary",
                        "content": fix_summary,
                        "branch": branch_name
                    },
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status not in [200, 201]:
                        error_text = await response.text()
                        self.logger.warning("Failed to create fix file", error=error_text)

                # Check if PR already exists for this branch
                pr_url = None
                pr_number = None
                async with session.get(
                    f"{self.base_url}/repos/{repo_owner}/{repo_name}/pulls?head={repo_owner}:{branch_name}&state=open",
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 200:
                        prs = await response.json()
                        if prs and len(prs) > 0:
                            pr_url = prs[0].get("html_url")
                            pr_number = prs[0].get("number")
                            self.logger.info("PR already exists, will update it", pr_url=pr_url)

                pr_body = self._build_pr_body(vulnerabilities[:5], fixes_applied)
                pr_title = f"Security Review: {len(vulnerabilities[:5])} vulnerabilities found - manual fixes required"

                if pr_number:
                    # Update existing PR
                    async with session.patch(
                        f"{self.base_url}/repos/{repo_owner}/{repo_name}/pulls/{pr_number}",
                        headers=headers,
                        json={
                            "title": pr_title,
                            "body": pr_body
                        },
                        timeout=aiohttp.ClientTimeout(total=30)
                    ) as response:
                        if response.status == 200:
                            self.logger.info("Updated existing security fix PR", pr_url=pr_url)
                            return pr_url
                        else:
                            error_text = await response.text()
                            self.logger.error("Failed to update PR", status=response.status, error=error_text)
                            return pr_url  # Return existing URL even if update failed
                else:
                    # Create new PR
                    async with session.post(
                        f"{self.base_url}/repos/{repo_owner}/{repo_name}/pulls",
                        headers=headers,
                        json={
                            "title": pr_title,
                            "body": pr_body,
                            "head": branch_name,
                            "base": base_branch
                        },
                        timeout=aiohttp.ClientTimeout(total=30)
                    ) as response:
                        if response.status == 201:
                            data = await response.json()
                            pr_url = data.get("html_url")
                            self.logger.info("Created security fix PR", pr_url=pr_url)
                            return pr_url
                        else:
                            error_text = await response.text()
                            self.logger.error("Failed to create PR", status=response.status, error=error_text)
                            return None

        except Exception as e:
            self.logger.error("GitHub API error creating fix PR", error=str(e))
            return None

    def _generate_fix_code(self, vulnerability: Vulnerability) -> Optional[str]:
        """Generate fix code for a vulnerability"""
        # Map common vulnerabilities to fixes
        fix_templates = {
            "SQL Injection": """
# Fix for SQL Injection
- Replace raw SQL queries with parameterized queries
- Use ORM methods instead of raw SQL
- Example:
  ```python
  # Before: VULNERABLE
  query = f"SELECT * FROM users WHERE id = {user_id}"

  # After: SECURE
  query = "SELECT * FROM users WHERE id = ?"
  cursor.execute(query, (user_id,))
  ```
""",
            "Cross-Site Scripting": """
# Fix for XSS
- Escape all user input before rendering
- Use Content Security Policy headers
- Example:
  ```python
  # Before: VULNERABLE
  return f"<div>{user_input}</div>"

  # After: SECURE
  from html import escape
  return f"<div>{escape(user_input)}</div>"
  ```
""",
            "Broken Access Control": """
# Fix for Broken Access Control
- Implement role-based access control (RBAC)
- Validate user permissions on every request
- Example:
  ```python
  # Before: VULNERABLE
  @app.route('/admin')
  def admin_panel():
      return render_template('admin.html')

  # After: SECURE
  @app.route('/admin')
  @require_role('admin')
  def admin_panel():
      return render_template('admin.html')
  ```
"""
        }

        for vuln_type, fix in fix_templates.items():
            if vuln_type.lower() in vulnerability.title.lower():
                return fix

        return vulnerability.recommendation

    def _build_fix_summary(self, vulnerabilities: List[Vulnerability], fixes_applied: list) -> str:
        """Build base64-encoded summary of fixes"""
        import base64

        summary = f"""# Security Review: Manual Fixes Required

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Vulnerabilities Found:** {len(vulnerabilities)}

## Overview

This document contains detailed security findings and fix recommendations. **No automated code changes were made** - please review and apply fixes manually.

## Vulnerabilities to Fix

"""
        for i, vuln in enumerate(vulnerabilities, 1):
            summary += f"\n### {i}. {vuln.title}\n\n"
            summary += f"**Severity:** {vuln.severity.value.upper()} (CVSS: {vuln.cvss_score})\n\n"

            # Try to extract actual file name from metadata if available
            file_name = vuln.affected_component
            if vuln.metadata and 'file_name' in vuln.metadata:
                file_name = vuln.metadata['file_name']

            summary += f"**Component:** `{file_name}`\n"
            if vuln.vulnerable_code_line:
                summary += f"**Line:** {vuln.vulnerable_code_line}\n"
            summary += f"\n**CWE:** {vuln.cwe_id} - {vuln.cwe_name}\n"
            summary += f"**OWASP:** {vuln.owasp_category.value}\n\n"

            summary += f"**Issue:**\n{vuln.description}\n\n"
            summary += f"**Impact:**\n{vuln.impact}\n\n"
            summary += f"**How to Fix:**\n{vuln.recommendation}\n\n"

            if vuln.remediation_steps:
                summary += "**Steps:**\n"
                for step in vuln.remediation_steps:
                    summary += f"- {step}\n"
                summary += "\n"

            if vuln.code_fix_example:
                summary += f"**Code Example:**\n```\n{vuln.code_fix_example}\n```\n\n"

            summary += "---\n"

        summary += """
## Next Steps

1. Review each vulnerability listed above
2. Locate the affected file and line number
3. Apply the recommended fixes
4. Run your test suite
5. Mark this PR as ready for review once fixes are applied

---
Generated by Agentic AI Cyber Protection System
"""
        return base64.b64encode(summary.encode()).decode()

    def _build_pr_body(self, vulnerabilities: List[Vulnerability], fixes_applied: list) -> str:
        """Build PR description"""
        body = f"""## Security Review Report

**Status:** Manual fixes required
**Vulnerabilities Found:** {len(vulnerabilities)}

This PR contains a detailed security analysis. **No automated code changes were made.** Please review the findings in `SECURITY_FIXES.md` and apply fixes manually.

### Vulnerabilities Identified

"""
        for i, vuln in enumerate(vulnerabilities, 1):
            severity_icon = {'critical': '[CRITICAL]', 'high': '[HIGH]', 'medium': '[MEDIUM]', 'low': '[LOW]'}.get(vuln.severity.value, '')

            # Try to extract actual file name from metadata if available
            file_name = vuln.affected_component
            if vuln.metadata and 'file_name' in vuln.metadata:
                file_name = vuln.metadata['file_name']

            body += f"{i}. {severity_icon} **{vuln.title}**\n"
            body += f"   - **Component:** `{file_name}`"
            if vuln.vulnerable_code_line:
                body += f" (Line {vuln.vulnerable_code_line})"
            body += f"\n"
            body += f"   - **CWE:** {vuln.cwe_id}\n"
            body += f"   - **CVSS:** {vuln.cvss_score}/10\n\n"

        body += """
### What's Included

See `SECURITY_FIXES.md` for:
- Detailed vulnerability descriptions
- Exact file and line numbers
- Step-by-step fix instructions
- Code examples

### Action Required

- [ ] Review `SECURITY_FIXES.md`
- [ ] Apply recommended fixes to the affected files
- [ ] Run test suite
- [ ] Update this PR with your fixes
- [ ] Request code review

### Review Notes

This is an automated security analysis. Please carefully review all recommendations before implementing fixes.

---
Generated with [Agentic Threat Modeling](https://github.com/yourusername/agentic-threat-modeling)
"""
        return body

    def generate_github_actions_workflow(self) -> str:
        """
        Generate a GitHub Actions workflow file for automated threat modeling on PRs

        Returns:
            YAML workflow file content
        """
        workflow = """name: Threat Modeling Analysis

on:
  pull_request:
    types: [opened, synchronize, reopened]
  workflow_dispatch:

jobs:
  threat-modeling:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          pip install -r requirements.txt

      - name: Run Threat Modeling Analysis
        env:
          MISTRAL_API_KEY: ${{ secrets.MISTRAL_API_KEY }}
          NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
        run: |
          python -m src.scripts.analyze_pr --repo ${{ github.repository }} --pr ${{ github.event.pull_request.number }}

      - name: Upload Analysis Report
        uses: actions/upload-artifact@v4
        with:
          name: threat-analysis-report
          path: reports/threat-analysis-*.html

      - name: Comment PR with Results
        if: always()
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const report = fs.readFileSync('reports/threat-summary.md', 'utf8');

            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: report
            });
"""
        return workflow

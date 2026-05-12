"""
Improved GitHub Integration using PyGithub library.
Replaces raw aiohttp calls with PyGithub's robust handling of pagination, rate limits, and API complexities.
"""

import os
import structlog
from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime
from github import Github, Repository, ContentFile
from github.GithubException import GithubException, RateLimitExceededException
import base64
import asyncio
from concurrent.futures import ThreadPoolExecutor

from src.models.threats import ThreatModel, Vulnerability
from src.utils.local_ingestion import CodeChunker

logger = structlog.get_logger()


class ImprovedGitHubIntegration:
    """
    Improved GitHub integration using PyGithub for better reliability and features.
    """

    def __init__(self, github_token: Optional[str] = None):
        """
        Initialize GitHub integration with PyGithub.

        Args:
            github_token: GitHub Personal Access Token (or from env: GITHUB_TOKEN)
        """
        self.github_token = github_token or os.getenv("GITHUB_TOKEN")

        if self.github_token:
            self.github = Github(self.github_token)
            self.logger = structlog.get_logger().bind(integration="github")
            self.executor = ThreadPoolExecutor(max_workers=5)  # For async compatibility
            self.code_chunker = CodeChunker()  # For tree-sitter parsing
        else:
            self.github = None
            self.logger = structlog.get_logger().bind(integration="github", status="no_token")
            self.logger.warning("GitHub token not configured")

    async def fetch_repository_code(
        self,
        repo_owner: str,
        repo_name: str,
        branch: str = "main",
        extensions: List[str] = None
    ) -> Tuple[List[Dict], str]:
        """
        Fetch and chunk repository code using PyGithub and tree-sitter.

        Args:
            repo_owner: Repository owner (username or org)
            repo_name: Repository name
            branch: Branch to analyze (default: main)
            extensions: File extensions to include (default: common code extensions)

        Returns:
            Tuple of (chunks, collection_id) where chunks are tree-sitter parsed code blocks
        """
        if not self.github:
            self.logger.error("GitHub client not initialized")
            return [], ""

        if extensions is None:
            extensions = ['.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.cpp', '.c', '.h', '.cs', '.go', '.rb']

        try:
            # Get repository
            repo = await self._run_in_executor(
                lambda: self.github.get_repo(f"{repo_owner}/{repo_name}")
            )

            # Auto-detect default branch if 'main' doesn't exist
            actual_branch = branch
            if branch == 'main':
                # Get the repository's default branch
                actual_branch = repo.default_branch
                self.logger.info(f"Using repository's default branch: {actual_branch}")

            self.logger.info(
                "Fetching repository",
                repo=f"{repo_owner}/{repo_name}",
                branch=actual_branch
            )

            # Get all files in the repository
            all_chunks = []
            processed_files = 0
            skipped_files = 0

            # Use get_contents with recursive=True for better performance
            contents = await self._run_in_executor(
                lambda: repo.get_contents("", ref=actual_branch)
            )

            files_to_process = []

            # Process directory structure
            while contents:
                file_content = contents.pop(0)
                if file_content.type == "dir":
                    # PyGithub handles pagination automatically
                    new_contents = await self._run_in_executor(
                        lambda fc=file_content: repo.get_contents(fc.path, ref=actual_branch)
                    )
                    contents.extend(new_contents)
                else:
                    # Check if file has relevant extension
                    if any(file_content.name.endswith(ext) for ext in extensions):
                        files_to_process.append(file_content)

            self.logger.info(f"Found {len(files_to_process)} code files to process")

            # Process files with rate limit awareness
            for file_content in files_to_process:
                try:
                    # Check rate limit (handle different PyGithub versions)
                    rate_limit = await self._run_in_executor(
                        lambda: self.github.get_rate_limit()
                    )

                    # Handle different PyGithub API versions
                    try:
                        # Try newer API first (rate.core)
                        if hasattr(rate_limit, 'rate') and hasattr(rate_limit.rate, 'remaining'):
                            remaining = rate_limit.rate.remaining
                            reset_time = rate_limit.rate.reset
                        # Older API (core.remaining)
                        elif hasattr(rate_limit, 'core'):
                            remaining = rate_limit.core.remaining
                            reset_time = rate_limit.core.reset
                        else:
                            # Skip rate limit check if structure is unknown
                            remaining = 100  # Assume we have quota
                            reset_time = datetime.now()

                        if remaining < 10:
                            self.logger.warning(
                                "Approaching rate limit",
                                remaining=remaining,
                                reset_time=reset_time
                            )
                            # Wait if needed
                            if remaining < 5:
                                wait_time = (reset_time - datetime.now()).total_seconds()
                                if wait_time > 0:
                                    self.logger.info(f"Waiting {wait_time}s for rate limit reset")
                                    await asyncio.sleep(wait_time)
                    except AttributeError as e:
                        # If rate limit check fails, log and continue
                        self.logger.debug(f"Rate limit check failed: {e}, continuing anyway")

                    # Get file content
                    if file_content.size > 1000000:  # Skip files > 1MB
                        self.logger.debug(f"Skipping large file: {file_content.path}")
                        skipped_files += 1
                        continue

                    # PyGithub automatically handles base64 decoding
                    file_data = await self._run_in_executor(
                        lambda fc=file_content: fc.decoded_content
                    )

                    # Save to temporary file for tree-sitter parsing
                    import tempfile
                    with tempfile.NamedTemporaryFile(
                        mode='wb',
                        suffix=os.path.splitext(file_content.name)[1],
                        delete=False
                    ) as tmp_file:
                        tmp_file.write(file_data)
                        tmp_path = tmp_file.name

                    try:
                        # Parse with tree-sitter
                        chunks = self.code_chunker.chunk_file(tmp_path)

                        # Update chunk metadata with GitHub info
                        for chunk in chunks:
                            chunk['file_path'] = file_content.path
                            chunk['repo'] = f"{repo_owner}/{repo_name}"
                            chunk['branch'] = actual_branch
                            chunk['sha'] = file_content.sha

                        all_chunks.extend(chunks)
                        processed_files += 1

                        if processed_files % 10 == 0:
                            self.logger.debug(f"Processed {processed_files} files")

                    finally:
                        # Clean up temp file
                        os.unlink(tmp_path)

                except RateLimitExceededException as e:
                    self.logger.error("Rate limit exceeded", error=str(e))
                    break
                except Exception as e:
                    self.logger.error(f"Error processing file {file_content.path}", error=str(e))
                    skipped_files += 1
                    continue

            # Store chunks in ChromaDB
            collection_id = ""
            if all_chunks:
                # Add to ChromaDB collection
                for chunk in all_chunks:
                    doc_text = f"{chunk['type']} {chunk['name']} in {chunk['file_path']}\n"
                    doc_text += f"Repository: {chunk['repo']} Branch: {chunk['branch']}\n"
                    doc_text += f"Lines {chunk['start_line']}-{chunk['end_line']}\n"
                    if chunk.get('docstring'):
                        doc_text += f"Docstring: {chunk['docstring']}\n"
                    doc_text += f"\n{chunk['content']}"

                    self.code_chunker.collection.add(
                        documents=[doc_text],
                        metadatas=[{
                            'type': chunk['type'],
                            'name': chunk['name'],
                            'file_path': chunk['file_path'],
                            'repo': chunk['repo'],
                            'branch': chunk['branch'],
                            'start_line': chunk['start_line'],
                            'end_line': chunk['end_line']
                        }],
                        ids=[chunk['chunk_id']]
                    )

                collection_id = self.code_chunker.collection.name

            self.logger.info(
                "Repository analysis complete",
                repo=f"{repo_owner}/{repo_name}",
                processed_files=processed_files,
                skipped_files=skipped_files,
                total_chunks=len(all_chunks)
            )

            return all_chunks, collection_id

        except GithubException as e:
            self.logger.error(
                "GitHub API error",
                error=str(e),
                status=e.status,
                data=e.data
            )
            return [], ""
        except Exception as e:
            self.logger.error("Unexpected error fetching repository", error=str(e))
            return [], ""

    async def create_issue_from_vulnerability(
        self,
        repo_owner: str,
        repo_name: str,
        vulnerability: Vulnerability
    ) -> Optional[str]:
        """
        Create a GitHub issue from a vulnerability using PyGithub.

        Args:
            repo_owner: Repository owner
            repo_name: Repository name
            vulnerability: Vulnerability to report

        Returns:
            Issue URL if created successfully
        """
        if not self.github:
            self.logger.warning("GitHub client not initialized")
            return None

        try:
            repo = await self._run_in_executor(
                lambda: self.github.get_repo(f"{repo_owner}/{repo_name}")
            )

            # Build issue title and body
            title = f"[Security] {vulnerability.title}"
            body = self._format_vulnerability_body(vulnerability)

            # Determine labels
            labels = ["security", vulnerability.severity.value]
            if vulnerability.owasp_category:
                labels.append("owasp-top-10")

            # Create issue using PyGithub
            issue = await self._run_in_executor(
                lambda: repo.create_issue(
                    title=title,
                    body=body,
                    labels=labels
                )
            )

            self.logger.info(
                "Created GitHub issue",
                issue_url=issue.html_url,
                issue_number=issue.number,
                vulnerability=vulnerability.title
            )

            return issue.html_url

        except GithubException as e:
            self.logger.error(
                "Failed to create issue",
                error=str(e),
                status=e.status
            )
            return None
        except Exception as e:
            self.logger.error("Unexpected error creating issue", error=str(e))
            return None

    async def comment_on_pr(
        self,
        repo_owner: str,
        repo_name: str,
        pr_number: int,
        threat_model: ThreatModel
    ) -> bool:
        """
        Add a threat analysis comment to a Pull Request using PyGithub.

        Args:
            repo_owner: Repository owner
            repo_name: Repository name
            pr_number: Pull request number
            threat_model: Threat model analysis results

        Returns:
            True if comment was added successfully
        """
        if not self.github:
            self.logger.warning("GitHub client not initialized")
            return False

        try:
            repo = await self._run_in_executor(
                lambda: self.github.get_repo(f"{repo_owner}/{repo_name}")
            )

            # Get the pull request
            pr = await self._run_in_executor(
                lambda: repo.get_pull(pr_number)
            )

            # Build comment
            comment = self._build_pr_comment(threat_model)

            # Add comment using PyGithub
            issue_comment = await self._run_in_executor(
                lambda: pr.create_issue_comment(comment)
            )

            self.logger.info(
                "Added threat analysis comment to PR",
                pr_number=pr_number,
                comment_id=issue_comment.id
            )

            return True

        except GithubException as e:
            self.logger.error(
                "Failed to comment on PR",
                error=str(e),
                status=e.status
            )
            return False
        except Exception as e:
            self.logger.error("Unexpected error commenting on PR", error=str(e))
            return False

    async def get_pr_files(
        self,
        repo_owner: str,
        repo_name: str,
        pr_number: int
    ) -> List[Dict[str, Any]]:
        """
        Get changed files in a pull request for targeted analysis.

        Args:
            repo_owner: Repository owner
            repo_name: Repository name
            pr_number: Pull request number

        Returns:
            List of changed files with their patches
        """
        if not self.github:
            return []

        try:
            repo = await self._run_in_executor(
                lambda: self.github.get_repo(f"{repo_owner}/{repo_name}")
            )

            pr = await self._run_in_executor(
                lambda: repo.get_pull(pr_number)
            )

            # Get files changed in PR
            files = await self._run_in_executor(
                lambda: list(pr.get_files())
            )

            changed_files = []
            for file in files:
                changed_files.append({
                    'filename': file.filename,
                    'status': file.status,
                    'additions': file.additions,
                    'deletions': file.deletions,
                    'changes': file.changes,
                    'patch': file.patch if hasattr(file, 'patch') else None,
                    'sha': file.sha
                })

            self.logger.info(
                "Retrieved PR files",
                pr_number=pr_number,
                file_count=len(changed_files)
            )

            return changed_files

        except Exception as e:
            self.logger.error("Error fetching PR files", error=str(e))
            return []

    async def _run_in_executor(self, func):
        """Run synchronous PyGithub calls in executor for async compatibility."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self.executor, func)

    def _format_vulnerability_body(self, vulnerability: Vulnerability) -> str:
        """Format vulnerability for GitHub issue body."""
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
"""

        # Add CVE data if available
        if vulnerability.metadata and 'related_cves' in vulnerability.metadata:
            cves = vulnerability.metadata['related_cves']
            if cves:
                body += "\n\n### Related CVEs\n"
                for cve in cves[:5]:
                    body += f"- [{cve['cve_id']}](https://nvd.nist.gov/vuln/detail/{cve['cve_id']}) - CVSS: {cve.get('cvss_score', 'N/A')}\n"

        body += "\n---\nGenerated with [Agentic Threat Modeling System](https://github.com/yourusername/agentic-threat-modeling)"

        return body

    def _build_pr_comment(self, threat_model: ThreatModel) -> str:
        """Build formatted comment for PR."""
        # Calculate severity distribution
        severity_counts = {}
        for vuln in threat_model.vulnerabilities:
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

        if threat_model.critical_paths:
            comment += "\n### Attack Paths Identified\n\n"
            for i, path in enumerate(threat_model.critical_paths[:3], 1):
                comment += f"{i}. **{path.name}**\n"
                comment += f"   - Probability: {path.probability:.0%}\n"
                comment += f"   - Damage: {path.potential_damage.value}\n"
                comment += f"   - Steps: {len(path.intermediate_steps)}\n\n"

        comment += f"\n### Agent Analyses\n\n"
        for agent_name, analysis in threat_model.agent_analyses.items():
            if isinstance(analysis, str):
                comment += f"- **{agent_name}:** {analysis[:100]}...\n"

        comment += f"\n---\nGenerated with Agentic Threat Modeling | Analysis ID: {datetime.now().strftime('%Y%m%d-%H%M%S')}\n"

        return comment


# Backward compatibility
class GitHubIntegration(ImprovedGitHubIntegration):
    """Wrapper for backward compatibility"""
    pass
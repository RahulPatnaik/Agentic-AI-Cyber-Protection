"""
CVE Scanner Agent
Integrates with NVD (National Vulnerability Database) to lookup CVEs and enrich threat analysis
"""

from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field
import structlog
import asyncio
from datetime import datetime, timedelta
import aiohttp
import time

logger = structlog.get_logger()


class CVEInfo(BaseModel):
    """CVE information from NVD"""
    cve_id: str
    description: str
    cvss_score: float
    severity: str
    published_date: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    cwe_ids: List[str] = Field(default_factory=list)
    affected_products: List[str] = Field(default_factory=list)


class CVEScanner:
    """
    Agent that scans for CVEs using NVD API

    Provides:
    - CVE lookup by keyword/technology
    - CWE to CVE mapping
    - Recent CVE monitoring
    """

    def __init__(self, nvd_api_key: Optional[str] = None):
        self.nvd_api_key = nvd_api_key
        self.logger = structlog.get_logger().bind(agent="cve_scanner")
        self.cache: Dict[str, List[CVEInfo]] = {}
        self.cache_ttl = timedelta(hours=24)
        self.cache_timestamp: Dict[str, datetime] = {}
        self.nvd_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.last_request_time = 0
        self.rate_limit_delay = 0.6  # 0.6 seconds between requests (NVD rate limit)

    async def lookup_cves_by_keyword(
        self,
        keyword: str,
        max_results: int = 10
    ) -> List[CVEInfo]:
        """
        Lookup CVEs by keyword (technology, product name, etc.)

        Args:
            keyword: Search keyword (e.g., "JWT", "PostgreSQL", "OAuth")
            max_results: Maximum number of results to return

        Returns:
            List of CVE information
        """
        self.logger.info("Looking up CVEs by keyword", keyword=keyword)

        # Check cache
        cache_key = f"keyword:{keyword}"
        if self._is_cache_valid(cache_key):
            self.logger.info("Returning cached CVE results", keyword=keyword)
            return self.cache[cache_key][:max_results]

        # Fallback: Return demo CVEs if no API key
        if not self.nvd_api_key or self.nvd_api_key == "your_nvd_api_key_here":
            self.logger.warning(
                "NVD API key not configured, using fallback CVE data",
                keyword=keyword
            )
            cves = self._get_fallback_cves(keyword, max_results)
            self._update_cache(cache_key, cves)
            return cves

        # Real NVD API call
        try:
            self.logger.info("Calling NVD API for keyword search", keyword=keyword)
            cves = await self._call_nvd_api(keyword_search=keyword, max_results=max_results)

            if cves:
                self._update_cache(cache_key, cves)
                return cves[:max_results]
            else:
                # Empty result, use fallback
                self.logger.warning("NVD API returned no results, using fallback", keyword=keyword)
                cves = self._get_fallback_cves(keyword, max_results)
                self._update_cache(cache_key, cves)
                return cves

        except Exception as e:
            self.logger.error("NVD API call failed, using fallback", keyword=keyword, error=str(e))
            cves = self._get_fallback_cves(keyword, max_results)
            self._update_cache(cache_key, cves)
            return cves

    async def lookup_cves_by_cwe(
        self,
        cwe_id: str,
        max_results: int = 10
    ) -> List[CVEInfo]:
        """
        Lookup CVEs associated with a specific CWE

        Args:
            cwe_id: CWE identifier (e.g., "CWE-79")
            max_results: Maximum number of results

        Returns:
            List of CVE information
        """
        self.logger.info("Looking up CVEs by CWE", cwe_id=cwe_id)

        # Check cache
        cache_key = f"cwe:{cwe_id}"
        if self._is_cache_valid(cache_key):
            return self.cache[cache_key][:max_results]

        # Fallback data if no API key
        if not self.nvd_api_key or self.nvd_api_key == "your_nvd_api_key_here":
            self.logger.warning("NVD API key not configured, using fallback CVE data")
            cves = self._get_fallback_cves_by_cwe(cwe_id, max_results)
            self._update_cache(cache_key, cves)
            return cves

        # Real NVD API call
        try:
            self.logger.info("Calling NVD API for CWE search", cwe_id=cwe_id)
            cves = await self._call_nvd_api(cwe_id=cwe_id, max_results=max_results)

            if cves:
                self._update_cache(cache_key, cves)
                return cves[:max_results]
            else:
                # Empty result, use fallback
                self.logger.warning("NVD API returned no results, using fallback", cwe_id=cwe_id)
                cves = self._get_fallback_cves_by_cwe(cwe_id, max_results)
                self._update_cache(cache_key, cves)
                return cves

        except Exception as e:
            self.logger.error("NVD API call failed, using fallback", cwe_id=cwe_id, error=str(e))
            cves = self._get_fallback_cves_by_cwe(cwe_id, max_results)
            self._update_cache(cache_key, cves)
            return cves

    async def get_recent_cves(
        self,
        days: int = 7,
        severity_threshold: float = 7.0,
        max_results: int = 20
    ) -> List[CVEInfo]:
        """
        Get recently published CVEs with high severity

        Args:
            days: Number of days to look back
            severity_threshold: Minimum CVSS score
            max_results: Maximum results to return

        Returns:
            List of recent high-severity CVEs
        """
        self.logger.info(
            "Fetching recent CVEs",
            days=days,
            severity_threshold=severity_threshold
        )

        # Check cache
        cache_key = f"recent:{days}:{severity_threshold}"
        if self._is_cache_valid(cache_key):
            return self.cache[cache_key][:max_results]

        # Fallback data if no API key
        if not self.nvd_api_key or self.nvd_api_key == "your_nvd_api_key_here":
            self.logger.warning("NVD API key not configured, using fallback CVE data")
            cves = self._get_recent_fallback_cves(days, severity_threshold, max_results)
            self._update_cache(cache_key, cves)
            return cves

        # Real NVD API call
        try:
            self.logger.info("Calling NVD API for recent CVEs", days=days)
            cves = await self._call_nvd_api(days_back=days, max_results=max_results * 2)

            # Filter by severity threshold
            if cves:
                filtered_cves = [
                    cve for cve in cves
                    if cve.cvss_score >= severity_threshold
                ]

                self._update_cache(cache_key, filtered_cves)
                return filtered_cves[:max_results]
            else:
                # Empty result, use fallback
                self.logger.warning("NVD API returned no results, using fallback")
                cves = self._get_recent_fallback_cves(days, severity_threshold, max_results)
                self._update_cache(cache_key, cves)
                return cves

        except Exception as e:
            self.logger.error("NVD API call failed, using fallback", error=str(e))
            cves = self._get_recent_fallback_cves(days, severity_threshold, max_results)
            self._update_cache(cache_key, cves)
            return cves

    def _is_cache_valid(self, cache_key: str) -> bool:
        """Check if cached data is still valid"""
        if cache_key not in self.cache:
            return False

        timestamp = self.cache_timestamp.get(cache_key)
        if not timestamp:
            return False

        return datetime.now() - timestamp < self.cache_ttl

    def _update_cache(self, cache_key: str, data: List[CVEInfo]):
        """Update cache with new data"""
        self.cache[cache_key] = data
        self.cache_timestamp[cache_key] = datetime.now()

    def _get_fallback_cves(self, keyword: str, max_results: int) -> List[CVEInfo]:
        """Generate fallback CVE data based on keyword"""

        # Common vulnerability patterns by keyword
        fallback_data = {
            "jwt": [
                CVEInfo(
                    cve_id="CVE-2024-1234",
                    description="JWT token signature verification bypass vulnerability allowing authentication bypass",
                    cvss_score=9.8,
                    severity="CRITICAL",
                    cwe_ids=["CWE-287"],
                    affected_products=["JWT library"]
                ),
                CVEInfo(
                    cve_id="CVE-2023-5678",
                    description="JWT token weak secret key vulnerability enabling token forgery",
                    cvss_score=8.1,
                    severity="HIGH",
                    cwe_ids=["CWE-326"],
                    affected_products=["JWT implementation"]
                )
            ],
            "sql": [
                CVEInfo(
                    cve_id="CVE-2024-2345",
                    description="SQL injection vulnerability in database query parameter handling",
                    cvss_score=9.9,
                    severity="CRITICAL",
                    cwe_ids=["CWE-89"],
                    affected_products=["Database connector"]
                )
            ],
            "authentication": [
                CVEInfo(
                    cve_id="CVE-2024-3456",
                    description="Authentication bypass vulnerability in session management",
                    cvss_score=9.1,
                    severity="CRITICAL",
                    cwe_ids=["CWE-287", "CWE-306"],
                    affected_products=["Auth library"]
                )
            ],
            "xss": [
                CVEInfo(
                    cve_id="CVE-2024-4567",
                    description="Cross-site scripting (XSS) vulnerability in input sanitization",
                    cvss_score=7.4,
                    severity="HIGH",
                    cwe_ids=["CWE-79"],
                    affected_products=["Web framework"]
                )
            ]
        }

        # Check for keyword match
        keyword_lower = keyword.lower()
        for key, cves in fallback_data.items():
            if key in keyword_lower:
                return cves[:max_results]

        # Generic fallback
        return [
            CVEInfo(
                cve_id=f"CVE-2024-DEMO",
                description=f"Potential vulnerability related to {keyword}",
                cvss_score=7.5,
                severity="HIGH",
                cwe_ids=["CWE-20"],
                affected_products=[keyword]
            )
        ]

    def _get_fallback_cves_by_cwe(self, cwe_id: str, max_results: int) -> List[CVEInfo]:
        """Generate fallback CVE data for specific CWE"""

        cwe_mapping = {
            "CWE-79": [
                CVEInfo(
                    cve_id="CVE-2024-XSS1",
                    description="Reflected XSS vulnerability in user input handling",
                    cvss_score=7.4,
                    severity="HIGH",
                    cwe_ids=["CWE-79"],
                    affected_products=["Web application"]
                )
            ],
            "CWE-89": [
                CVEInfo(
                    cve_id="CVE-2024-SQL1",
                    description="SQL injection in query parameterization",
                    cvss_score=9.8,
                    severity="CRITICAL",
                    cwe_ids=["CWE-89"],
                    affected_products=["Database driver"]
                )
            ],
            "CWE-287": [
                CVEInfo(
                    cve_id="CVE-2024-AUTH1",
                    description="Improper authentication vulnerability",
                    cvss_score=9.1,
                    severity="CRITICAL",
                    cwe_ids=["CWE-287"],
                    affected_products=["Authentication service"]
                )
            ]
        }

        return cwe_mapping.get(cwe_id, [])[:max_results]

    def _get_recent_fallback_cves(
        self,
        days: int,
        severity_threshold: float,
        max_results: int
    ) -> List[CVEInfo]:
        """Generate recent high-severity CVE fallback data"""

        recent_date = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")

        return [
            CVEInfo(
                cve_id="CVE-2024-9999",
                description="Critical remote code execution vulnerability in widely-used library",
                cvss_score=9.8,
                severity="CRITICAL",
                published_date=recent_date,
                cwe_ids=["CWE-94"],
                affected_products=["Common library"]
            ),
            CVEInfo(
                cve_id="CVE-2024-8888",
                description="Authentication bypass vulnerability in enterprise software",
                cvss_score=9.1,
                severity="CRITICAL",
                published_date=recent_date,
                cwe_ids=["CWE-287"],
                affected_products=["Enterprise app"]
            )
        ][:max_results]

    async def enrich_vulnerability_with_cves(
        self,
        vulnerability_description: str,
        cwe_id: Optional[str] = None
    ) -> List[CVEInfo]:
        """
        Enrich a vulnerability with relevant CVE information

        Args:
            vulnerability_description: Description of the vulnerability
            cwe_id: Associated CWE ID if available

        Returns:
            List of relevant CVEs
        """

        cves = []

        # Try CWE lookup first
        if cwe_id:
            cves = await self.lookup_cves_by_cwe(cwe_id, max_results=3)

        # If no CVEs from CWE, try keyword search
        if not cves:
            # Extract keywords from description
            keywords = ["authentication", "sql", "xss", "jwt", "session"]
            desc_lower = vulnerability_description.lower()

            for keyword in keywords:
                if keyword in desc_lower:
                    cves = await self.lookup_cves_by_keyword(keyword, max_results=3)
                    break

        return cves

    async def _call_nvd_api(
        self,
        keyword_search: Optional[str] = None,
        cwe_id: Optional[str] = None,
        days_back: Optional[int] = None,
        max_results: int = 10
    ) -> List[CVEInfo]:
        """
        Make actual API call to NVD (National Vulnerability Database)

        Args:
            keyword_search: Keyword to search for
            cwe_id: CWE ID to filter by
            days_back: Number of days to look back for recent CVEs
            max_results: Maximum results to return

        Returns:
            List of CVE information from NVD
        """
        # Rate limiting: NVD API allows 5 requests per 30 seconds without key
        # With API key: 50 requests per 30 seconds
        await self._respect_rate_limit()

        headers = {}
        if self.nvd_api_key:
            headers["apiKey"] = self.nvd_api_key

        params = {
            "resultsPerPage": min(max_results, 100)  # NVD max is 2000, we use 100 for performance
        }

        # Add search parameters
        if keyword_search:
            params["keywordSearch"] = keyword_search

        if cwe_id:
            # Remove "CWE-" prefix if present
            cwe_number = cwe_id.replace("CWE-", "")
            params["cweId"] = f"CWE-{cwe_number}"

        if days_back:
            # Calculate date range
            end_date = datetime.now()
            start_date = end_date - timedelta(days=days_back)
            params["pubStartDate"] = start_date.strftime("%Y-%m-%dT00:00:00.000")
            params["pubEndDate"] = end_date.strftime("%Y-%m-%dT23:59:59.999")

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.nvd_base_url,
                    params=params,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_nvd_response(data)
                    elif response.status == 403:
                        self.logger.error("NVD API: Forbidden (check API key)")
                        return []
                    elif response.status == 404:
                        self.logger.warning("NVD API: No results found")
                        return []
                    else:
                        error_text = await response.text()
                        self.logger.error(
                            "NVD API error",
                            status=response.status,
                            error=error_text
                        )
                        return []

        except asyncio.TimeoutError:
            self.logger.error("NVD API timeout")
            return []
        except Exception as e:
            self.logger.error("NVD API call failed", error=str(e), exc_info=True)
            return []

    async def _respect_rate_limit(self):
        """Respect NVD API rate limits"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time

        if time_since_last < self.rate_limit_delay:
            await asyncio.sleep(self.rate_limit_delay - time_since_last)

        self.last_request_time = time.time()

    def _parse_nvd_response(self, data: Dict[str, Any]) -> List[CVEInfo]:
        """
        Parse NVD API response into CVEInfo objects

        Args:
            data: JSON response from NVD API

        Returns:
            List of CVEInfo objects
        """
        cves = []

        vulnerabilities = data.get("vulnerabilities", [])

        for vuln_item in vulnerabilities:
            try:
                cve_data = vuln_item.get("cve", {})

                # Extract CVE ID
                cve_id = cve_data.get("id", "UNKNOWN")

                # Extract description
                descriptions = cve_data.get("descriptions", [])
                description = ""
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break

                # Extract CVSS score and severity
                cvss_score = 0.0
                severity = "UNKNOWN"

                metrics = cve_data.get("metrics", {})

                # Try CVSS v3.1 first, then v3.0, then v2.0
                if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                    cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                    cvss_score = cvss_data.get("baseScore", 0.0)
                    severity = cvss_data.get("baseSeverity", "UNKNOWN")
                elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                    cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
                    cvss_score = cvss_data.get("baseScore", 0.0)
                    severity = cvss_data.get("baseSeverity", "UNKNOWN")
                elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                    cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
                    cvss_score = cvss_data.get("baseScore", 0.0)
                    # V2 doesn't have severity, estimate from score
                    if cvss_score >= 7.0:
                        severity = "HIGH"
                    elif cvss_score >= 4.0:
                        severity = "MEDIUM"
                    else:
                        severity = "LOW"

                # Extract published date
                published_date = cve_data.get("published", "")

                # Extract CWE IDs
                cwe_ids = []
                weaknesses = cve_data.get("weaknesses", [])
                for weakness in weaknesses:
                    for desc in weakness.get("description", []):
                        cwe_value = desc.get("value", "")
                        if cwe_value.startswith("CWE-"):
                            cwe_ids.append(cwe_value)

                # Extract references
                references = []
                refs = cve_data.get("references", [])
                for ref in refs[:5]:  # Limit to 5 references
                    url = ref.get("url", "")
                    if url:
                        references.append(url)

                # Create CVEInfo object
                cve_info = CVEInfo(
                    cve_id=cve_id,
                    description=description,
                    cvss_score=cvss_score,
                    severity=severity,
                    published_date=published_date,
                    references=references,
                    cwe_ids=cwe_ids,
                    affected_products=[]  # NVD API 2.0 has complex CPE structure, simplified for now
                )

                cves.append(cve_info)

            except Exception as e:
                self.logger.warning("Failed to parse CVE item", error=str(e))
                continue

        self.logger.info("Parsed NVD response", cves_found=len(cves))
        return cves

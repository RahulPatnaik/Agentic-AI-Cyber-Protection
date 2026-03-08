"""
Test Runner Script
Runs all tests and generates summary report
"""

import asyncio
import sys
from pathlib import Path
import time
from datetime import datetime
import json
import os

# CRITICAL: Load .env BEFORE importing any agents
from dotenv import load_dotenv
env_path = Path(__file__).parent.parent / ".env"
load_dotenv(env_path, override=True)

# Verify API key is loaded
if not os.getenv('MISTRAL_API_KEY'):
    print("\n⚠️  ERROR: MISTRAL_API_KEY not found in .env file!")
    print(f"Looking for .env at: {env_path}")
    print("Please check your .env file contains: MISTRAL_API_KEY=your_key_here\n")
    sys.exit(1)

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.config import Settings
from src.parsers.nlp_parser import NLPParser
from src.agents.orchestrator import ThreatModelingOrchestrator


class TestRunner:
    """Runs comprehensive test suite and generates report"""

    def __init__(self):
        self.settings = Settings()
        self.nlp_parser = NLPParser(self.settings)
        self.orchestrator = ThreatModelingOrchestrator(self.settings)
        self.results = {
            'total_tests': 0,
            'passed': 0,
            'failed': 0,
            'test_details': [],
            'start_time': None,
            'end_time': None,
            'total_duration': 0
        }

    async def run_test(self, test_name, description, code_snippet=None, expected_vuln_type=None):
        """Run a single test case"""

        print(f"\n{'='*80}")
        print(f"Running: {test_name}")
        print(f"{'='*80}")

        test_result = {
            'name': test_name,
            'description': description[:100] + '...' if len(description) > 100 else description,
            'passed': False,
            'duration': 0,
            'vulnerabilities_found': 0,
            'critical_count': 0,
            'high_count': 0,
            'error': None
        }

        try:
            start = time.time()

            # Parse and analyze
            asset = await self.nlp_parser.parse_description(description, code_snippet)
            threat_model = await self.orchestrator.analyze(asset)

            duration = time.time() - start

            # Collect results
            test_result['duration'] = round(duration, 2)
            test_result['vulnerabilities_found'] = len(threat_model.vulnerabilities)
            test_result['critical_count'] = len([v for v in threat_model.vulnerabilities if v.severity.value == 'critical'])
            test_result['high_count'] = len([v for v in threat_model.vulnerabilities if v.severity.value == 'high'])
            test_result['confidence_score'] = threat_model.confidence_score
            test_result['attack_paths'] = len(threat_model.attack_paths)

            # Check if expected vulnerability type was found
            if expected_vuln_type:
                found = any(expected_vuln_type.lower() in v.title.lower() for v in threat_model.vulnerabilities)
                test_result['passed'] = found
                test_result['expected_found'] = found
            else:
                # For tests without specific expectations, pass if vulnerabilities were found
                test_result['passed'] = len(threat_model.vulnerabilities) > 0

            # Print summary
            print(f"\n✓ Test completed in {duration:.2f}s")
            print(f"  Vulnerabilities: {test_result['vulnerabilities_found']} (Critical: {test_result['critical_count']}, High: {test_result['high_count']})")
            print(f"  Attack Paths: {test_result['attack_paths']}")
            print(f"  Confidence: {test_result['confidence_score']}")

            if expected_vuln_type:
                if test_result['passed']:
                    print(f"  ✓ Expected vulnerability type '{expected_vuln_type}' FOUND")
                else:
                    print(f"  ✗ Expected vulnerability type '{expected_vuln_type}' NOT FOUND")

            if test_result['passed']:
                self.results['passed'] += 1
            else:
                self.results['failed'] += 1

        except Exception as e:
            test_result['error'] = str(e)
            test_result['passed'] = False
            self.results['failed'] += 1
            print(f"\n✗ Test FAILED with error: {str(e)}")

        self.results['test_details'].append(test_result)
        self.results['total_tests'] += 1

    async def run_all_tests(self):
        """Run comprehensive test suite"""

        print("\n" + "="*80)
        print("AGENTIC THREAT MODELING SYSTEM - COMPREHENSIVE TEST SUITE")
        print("="*80)

        self.results['start_time'] = datetime.now().isoformat()
        overall_start = time.time()

        # Category 1: SQL Injection Tests
        print("\n\n### CATEGORY 1: SQL INJECTION DETECTION ###\n")

        await self.run_test(
            "Test 1: SQL Injection - String Concatenation",
            """
            User login endpoint that accepts username and password.
            The code builds a SQL query using string concatenation without any validation.
            """,
            """
def login(username, password):
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    result = db.execute(query)
    return result
            """,
            expected_vuln_type="SQL Injection"
        )

        await self.run_test(
            "Test 2: SQL Injection - No Input Validation",
            """
            E-commerce search functionality that builds SQL queries from user input.
            Product search accepts category and price range parameters.
            No sanitization or parameterized queries used.
            """,
            expected_vuln_type="injection"
        )

        # Category 2: XSS Tests
        print("\n\n### CATEGORY 2: CROSS-SITE SCRIPTING (XSS) ###\n")

        await self.run_test(
            "Test 3: Reflected XSS - Unencoded Output",
            """
            Web application search page that displays user search queries.
            Search term is directly embedded in HTML response without encoding.
            """,
            """
def search_results(query):
    return f"<h1>Results for: {query}</h1>"
            """,
            expected_vuln_type="XSS"
        )

        await self.run_test(
            "Test 4: Stored XSS - User Comments",
            """
            Blog platform where users can post comments.
            Comments are stored in database and displayed on page without sanitization.
            No output encoding or CSP headers.
            """,
            expected_vuln_type="XSS"
        )

        # Category 3: Authentication Vulnerabilities
        print("\n\n### CATEGORY 3: AUTHENTICATION & ACCESS CONTROL ###\n")

        await self.run_test(
            "Test 5: Missing Authentication on PII Endpoint",
            """
            REST API endpoint /api/users/{id}/profile that returns user personal information.
            No authentication required to access this endpoint.
            Returns email, phone number, address, date of birth.
            """,
            expected_vuln_type="authentication"
        )

        await self.run_test(
            "Test 6: Broken Access Control - IDOR",
            """
            User profile API where authenticated users can view profiles by user ID.
            No authorization check to verify if the user owns the requested profile.
            Users can access other users' private data by changing the ID parameter.
            """,
            expected_vuln_type="access control"
        )

        await self.run_test(
            "Test 7: Weak Password Policy",
            """
            User registration system with no password complexity requirements.
            Allows passwords as short as 4 characters.
            No MFA or account lockout after failed attempts.
            """,
            expected_vuln_type="authentication"
        )

        # Category 4: Cryptographic Failures
        print("\n\n### CATEGORY 4: CRYPTOGRAPHIC FAILURES ###\n")

        await self.run_test(
            "Test 8: Unencrypted PII Storage",
            """
            PostgreSQL database storing patient medical records.
            Contains SSN, diagnosis, treatment history, insurance info.
            All data stored in plaintext with no encryption at rest.
            HIPAA-regulated healthcare application.
            """,
            expected_vuln_type="encrypt"
        )

        await self.run_test(
            "Test 9: Unencrypted Data in Transit",
            """
            Mobile banking app that sends account balances and transaction data.
            API uses HTTP instead of HTTPS for communication.
            Transmits credit card numbers and account credentials.
            """,
            expected_vuln_type="encrypt"
        )

        await self.run_test(
            "Test 10: Weak Password Hashing",
            """
            Authentication system that stores user passwords.
            Uses MD5 hashing algorithm without salt.
            """,
            """
import hashlib
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
            """,
            expected_vuln_type="crypto"
        )

        # Category 5: Security Misconfiguration
        print("\n\n### CATEGORY 5: SECURITY MISCONFIGURATION ###\n")

        await self.run_test(
            "Test 11: Debug Mode in Production",
            """
            Flask web application deployed to production environment.
            Debug mode is enabled showing detailed stack traces to users.
            Environment variables and internal paths are exposed in error pages.
            """,
            expected_vuln_type="misconfiguration"
        )

        await self.run_test(
            "Test 12: Default Credentials",
            """
            Database server using default administrator credentials.
            Username: admin, Password: admin123.
            MongoDB instance accessible on default port 27017.
            """,
            expected_vuln_type="default"
        )

        # Category 6: DFD Generation & Analysis
        print("\n\n### CATEGORY 6: DATA FLOW DIAGRAM GENERATION ###\n")

        await self.run_test(
            "Test 13: Multi-Component System DFD",
            """
            E-commerce platform architecture:
            - Frontend: React web application
            - API Gateway: Node.js Express
            - Authentication Service: Python/FastAPI with JWT
            - Product Catalog Service: Java Spring Boot
            - Order Processing Service: Go microservice
            - Payment Service: Stripe integration
            - PostgreSQL database for users and orders
            - MongoDB for product catalog
            - Redis cache for session management
            """,
            expected_vuln_type=None  # Just check DFD generation
        )

        await self.run_test(
            "Test 14: Trust Boundary Analysis",
            """
            Healthcare system with multiple trust zones:
            - Public internet users accessing patient portal
            - Internal staff network accessing EHR system
            - DMZ hosting API gateway
            - Secure database zone with patient records
            - External pharmacy API integration
            Data flows across all boundaries without encryption.
            """,
            expected_vuln_type="encrypt"
        )

        # Category 7: Attack Path Prediction
        print("\n\n### CATEGORY 7: ATTACK PATH PREDICTION ###\n")

        await self.run_test(
            "Test 15: Multi-Stage Attack Chain",
            """
            Web application with the following weaknesses:
            - SQL injection in login form
            - Stored XSS in user profile
            - Admin panel accessible after login with no additional auth
            - File upload functionality in admin panel with no validation
            - Server has sudo privileges for web user
            """,
            expected_vuln_type="injection"
        )

        await self.run_test(
            "Test 16: Privilege Escalation Path",
            """
            API with broken access control allowing regular users to:
            1. View other users' API keys through insecure direct object reference
            2. Use stolen API keys to access admin endpoints
            3. Admin endpoints allow user role modification
            4. Modified roles persist and grant permanent admin access
            """,
            expected_vuln_type="access control"
        )

        # Category 8: MAESTRO Principles
        print("\n\n### CATEGORY 8: MAESTRO SECURITY PRINCIPLES ###\n")

        await self.run_test(
            "Test 17: MAESTRO Violations - Comprehensive",
            """
            Payment processing microservice with multiple security gaps:
            - No input validation (violates Trust But Verify)
            - No authentication required (violates Authentication & Authorization)
            - Stores credit cards in plaintext (violates Secure Defaults)
            - Single point of failure, no redundancy (violates Resilience)
            - No logging or monitoring (violates Observability)
            - All functionality exposed on public endpoint (violates Minimize Attack Surface)
            """,
            expected_vuln_type=None  # Tests MAESTRO validation
        )

        # Category 9: Performance Tests
        print("\n\n### CATEGORY 9: PERFORMANCE & SCALABILITY ###\n")

        await self.run_test(
            "Test 18: Simple System Analysis Speed",
            """
            Basic REST API with user authentication and PostgreSQL database.
            """,
            expected_vuln_type=None
        )

        await self.run_test(
            "Test 19: Complex System Analysis",
            """
            Large-scale distributed system:
            - 12 microservices (Node.js, Python, Java, Go)
            - 5 databases (PostgreSQL, MongoDB, Redis, Elasticsearch, Neo4j)
            - Message queues (RabbitMQ, Kafka)
            - Multiple external APIs (payment, shipping, email, SMS)
            - Load balancers, API gateways, service mesh
            - Kubernetes deployment with 50+ pods
            """,
            expected_vuln_type=None
        )

        # Category 10: Edge Cases
        print("\n\n### CATEGORY 10: EDGE CASES & ERROR HANDLING ###\n")

        await self.run_test(
            "Test 20: Minimal Input",
            """
            A web application with a database.
            """,
            expected_vuln_type=None
        )

        # Calculate overall results
        overall_duration = time.time() - overall_start
        self.results['end_time'] = datetime.now().isoformat()
        self.results['total_duration'] = round(overall_duration, 2)

        # Generate report
        self.generate_report()

    def generate_report(self):
        """Generate comprehensive test report"""

        print("\n\n" + "="*80)
        print("TEST SUITE SUMMARY")
        print("="*80)

        print(f"\nTotal Tests: {self.results['total_tests']}")
        print(f"Passed: {self.results['passed']} ({self.results['passed']/self.results['total_tests']*100:.1f}%)")
        print(f"Failed: {self.results['failed']} ({self.results['failed']/self.results['total_tests']*100:.1f}%)")
        print(f"Total Duration: {self.results['total_duration']:.2f}s")
        print(f"Average per Test: {self.results['total_duration']/self.results['total_tests']:.2f}s")

        # Detailed results
        print("\n" + "="*80)
        print("DETAILED RESULTS")
        print("="*80)

        for i, test in enumerate(self.results['test_details'], 1):
            status = "✓ PASS" if test['passed'] else "✗ FAIL"
            print(f"\n{i}. {test['name']}: {status}")
            print(f"   Duration: {test['duration']}s")
            print(f"   Vulnerabilities: {test['vulnerabilities_found']} (Critical: {test['critical_count']}, High: {test['high_count']})")
            if 'attack_paths' in test:
                print(f"   Attack Paths: {test['attack_paths']}")
            if 'confidence_score' in test:
                print(f"   Confidence: {test['confidence_score']}")
            if test.get('error'):
                print(f"   Error: {test['error']}")

        # Calculate metrics
        total_vulns = sum(t['vulnerabilities_found'] for t in self.results['test_details'])
        total_critical = sum(t['critical_count'] for t in self.results['test_details'])
        total_high = sum(t['high_count'] for t in self.results['test_details'])
        avg_duration = sum(t['duration'] for t in self.results['test_details']) / len(self.results['test_details'])

        print("\n" + "="*80)
        print("AGGREGATE METRICS")
        print("="*80)
        print(f"\nTotal Vulnerabilities Detected: {total_vulns}")
        print(f"Critical Vulnerabilities: {total_critical}")
        print(f"High Vulnerabilities: {total_high}")
        print(f"Average Analysis Time: {avg_duration:.2f}s")

        # Save to JSON
        report_path = Path(__file__).parent / "test_results.json"
        with open(report_path, 'w') as f:
            json.dump(self.results, f, indent=2)

        print(f"\n✓ Full report saved to: {report_path}")

        # Generate markdown report
        self.generate_markdown_report()

    def generate_markdown_report(self):
        """Generate markdown test report for presentation"""

        report = f"""# Agentic Threat Modeling System - Test Results

**Date:** {self.results['start_time']}
**Total Duration:** {self.results['total_duration']}s

## Summary

| Metric | Value |
|--------|-------|
| Total Tests | {self.results['total_tests']} |
| Passed | {self.results['passed']} ({self.results['passed']/self.results['total_tests']*100:.1f}%) |
| Failed | {self.results['failed']} ({self.results['failed']/self.results['total_tests']*100:.1f}%) |
| Total Vulnerabilities Detected | {sum(t['vulnerabilities_found'] for t in self.results['test_details'])} |
| Critical Findings | {sum(t['critical_count'] for t in self.results['test_details'])} |
| High Findings | {sum(t['high_count'] for t in self.results['test_details'])} |
| Average Analysis Time | {sum(t['duration'] for t in self.results['test_details'])/len(self.results['test_details']):.2f}s |

## Test Results by Category

### SQL Injection Detection
"""

        for test in self.results['test_details'][:2]:
            status = "✓" if test['passed'] else "✗"
            report += f"- {status} **{test['name']}** ({test['duration']}s) - {test['vulnerabilities_found']} vulnerabilities\n"

        report += "\n### Cross-Site Scripting (XSS)\n"
        for test in self.results['test_details'][2:4]:
            status = "✓" if test['passed'] else "✗"
            report += f"- {status} **{test['name']}** ({test['duration']}s) - {test['vulnerabilities_found']} vulnerabilities\n"

        report += "\n### Authentication & Access Control\n"
        for test in self.results['test_details'][4:7]:
            status = "✓" if test['passed'] else "✗"
            report += f"- {status} **{test['name']}** ({test['duration']}s) - {test['vulnerabilities_found']} vulnerabilities\n"

        md_path = Path(__file__).parent / "TEST_REPORT.md"
        with open(md_path, 'w') as f:
            f.write(report)

        print(f"✓ Markdown report saved to: {md_path}")


async def main():
    """Main entry point"""

    # Check if Mistral API key is configured
    settings = Settings()
    if not settings.mistral_api_key:
        print("\n⚠️  WARNING: No Mistral API key found!")
        print("Tests will use fallback parser without LLM capabilities.")
        print("Set MISTRAL_API_KEY in .env file for full functionality.\n")

        response = input("Continue anyway? (y/n): ")
        if response.lower() != 'y':
            print("Exiting.")
            return

    runner = TestRunner()
    await runner.run_all_tests()


if __name__ == "__main__":
    asyncio.run(main())

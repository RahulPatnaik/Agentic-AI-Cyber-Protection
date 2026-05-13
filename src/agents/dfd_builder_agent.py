"""
DFD Builder Agent
Converts natural language descriptions into structured Data Flow Diagrams
Based on OWASP pytm methodology
"""

from pydantic_ai import Agent
from typing import List
import structlog

from src.models.dfd_components import (
    DataFlowDiagram,
    ExternalEntity,
    Process,
    DataStore,
    DataFlow,
    TrustBoundary,
    TrustLevel,
    DataClassification,
    TransportProtocol,
    AuthenticationMethod
)
from src.models.threats import AssetInput, Vulnerability
from src.config import Settings
# LLM generator removed - using heuristics for reliability

logger = structlog.get_logger()


# DFD Builder Agent
dfd_builder_agent = Agent(
    'mistral:mistral-small-latest',
    system_prompt="""You are an expert system architect specializing in Data Flow Diagram (DFD) modeling for threat analysis.

Your role is to analyze system descriptions and create structured DFD components:

DFD Components:
1. **ExternalEntity** - External actors (users, systems, APIs, attackers)
2. **Process** - Application logic, services, APIs that process data
3. **DataStore** - Databases, files, caches that store data
4. **DataFlow** - Movement of data between components
5. **TrustBoundary** - Security zones (Internet, DMZ, Internal, Database)

Security Analysis Focus:
- Identify what data is sensitive (PII, credentials, financial)
- Determine trust levels for each component
- Identify where encryption is needed
- Detect missing authentication/authorization
- Find input validation gaps
- Map trust boundary crossings

Example Analysis:
"A web app where users login to view their medical records from a PostgreSQL database"

Would generate:
- ExternalEntity: "User" (untrusted, can be malicious)
- Process: "Web Application" (medium trust, handles PII, needs auth)
- DataStore: "PostgreSQL Database" (high trust, stores PII, encrypted)
- DataFlow: "User -> Web App" (HTTPS, carries credentials)
- DataFlow: "Web App -> Database" (SQL, carries PII queries)
- TrustBoundary: Internet -> Internal Network

Return detailed DFD component specifications with security properties.
"""
)


class DFDBuilder:
    """Builds Data Flow Diagrams from system descriptions"""

    def __init__(self, settings: Settings):
        self.settings = settings
        logger.info("Initialized DFD Builder Agent")

    async def build_dfd(self, asset: AssetInput) -> DataFlowDiagram:
        """
        Build a Data Flow Diagram from system description.
        Using heuristics-based generation for reliability.

        Args:
            asset: Structured asset input

        Returns:
            Complete DataFlowDiagram
        """
        logger.info("Building DFD from system description")

        # Use heuristic-based generation (more reliable than LLM for Mermaid syntax)
        dfd = self._create_smart_dfd(asset)

        # Validate security controls
        issues = dfd.validate_security_controls()
        if issues:
            logger.warning("DFD security issues found", count=len(issues))

        return dfd

    def _create_smart_dfd(self, asset: AssetInput) -> DataFlowDiagram:
        """
        Create a DFD with intelligent defaults based on asset characteristics.
        This uses heuristics to build a realistic DFD structure.
        """
        dfd = DataFlowDiagram(
            name=f"Threat Model: {asset.component_type.value if asset.component_type else 'System'}",
            description=asset.description
        )

        desc_lower = asset.description.lower()

        # 1. Create multiple external entities for realistic architecture
        # End Users
        user_entity = ExternalEntity(
            name="End Users",
            description="External end users accessing the system",
            entity_type="user",
            trust_level=TrustLevel.UNTRUSTED,
            is_authenticated=False,
            can_be_malicious=True
        )
        dfd.external_entities.append(user_entity)

        # Admin Users if relevant
        if 'admin' in desc_lower or 'management' in desc_lower:
            admin_entity = ExternalEntity(
                name="Admin Portal",
                description="Administrative interface",
                entity_type="user",
                trust_level=TrustLevel.MEDIUM_TRUST,
                is_authenticated=True,
                can_be_malicious=False
            )
            dfd.external_entities.append(admin_entity)

        # External APIs if mentioned
        if 'api' in desc_lower or 'third' in desc_lower or 'external' in desc_lower:
            api_entity = ExternalEntity(
                name="3rd Party Services",
                description="External API integrations",
                entity_type="system",
                trust_level=TrustLevel.LOW_TRUST,
                is_authenticated=True,
                can_be_malicious=False
            )
            dfd.external_entities.append(api_entity)

        # 2. Create realistic multi-tier process architecture

        # Frontend Layer
        if any(x in desc_lower for x in ['web', 'ui', 'frontend', 'react', 'angular', 'vue', 'browser']):
            frontend_process = Process(
                name="React Frontend",
                description="Single-page application UI",
                trust_level=TrustLevel.LOW_TRUST,
                implementsAuthentication=False,
                implementsAuthorization=False,
                sanitizesInput=True,
                encodesOutput=True,
                processes_pii=False,
                processes_credentials=False,
                technology="React/Next.js",
                programming_language="JavaScript"
            )
            dfd.processes.append(frontend_process)

        # API Gateway/Load Balancer
        api_gateway = Process(
            name="API Gateway",
            description="Request routing, rate limiting, authentication",
            trust_level=TrustLevel.MEDIUM_TRUST,
            implementsAuthentication=True,
            implementsAuthorization=False,
            sanitizesInput=True,
            encodesOutput=False,
            processes_pii=False,
            processes_credentials=True,
            technology="Kong/Nginx",
            programming_language="Configuration"
        )
        dfd.processes.append(api_gateway)

        # Authentication Service
        if 'auth' in desc_lower or 'login' in desc_lower:
            auth_service = Process(
                name="Auth Service",
                description="OAuth2/JWT authentication",
                trust_level=TrustLevel.HIGH_TRUST,
                implementsAuthentication=True,
                implementsAuthorization=True,
                sanitizesInput=True,
                encodesOutput=False,
                processes_pii=True,
                processes_credentials=True,
                technology="Keycloak/Auth0",
                programming_language=asset.programming_languages[0] if asset.programming_languages else "Python"
            )
            dfd.processes.append(auth_service)

        # Main Business Logic
        app_process = Process(
            name="Business Logic Service",
            description="Core application logic and processing",
            trust_level=TrustLevel.MEDIUM_TRUST,
            implementsAuthentication=False,
            implementsAuthorization=True,
            sanitizesInput=False,  # Common vulnerability point
            encodesOutput=False,
            processes_pii=asset.data_sensitivity in ['high', 'critical'],
            processes_credentials='password' in desc_lower,
            technology=', '.join(asset.frameworks) if asset.frameworks else "Express/FastAPI",
            programming_language=asset.programming_languages[0] if asset.programming_languages else "Python"
        )
        dfd.processes.append(app_process)

        # Microservices
        if 'microservice' in desc_lower or 'distributed' in desc_lower:
            payment_service = Process(
                name="Payment Service",
                description="Payment processing microservice",
                trust_level=TrustLevel.HIGH_TRUST,
                implementsAuthentication=False,
                implementsAuthorization=True,
                sanitizesInput=True,
                encodesOutput=False,
                processes_pii=True,
                processes_credentials=False,
                technology="Stripe/PayPal SDK",
                programming_language="Python"
            )
            dfd.processes.append(payment_service)

            notification_service = Process(
                name="Notification Service",
                description="Email/SMS notifications",
                trust_level=TrustLevel.MEDIUM_TRUST,
                implementsAuthentication=False,
                implementsAuthorization=False,
                sanitizesInput=True,
                encodesOutput=True,
                processes_pii=True,
                processes_credentials=False,
                technology="SendGrid/Twilio",
                programming_language="Node.js"
            )
            dfd.processes.append(notification_service)

        # 3. Create data store if database mentioned
        if any(db in asset.description.lower() for db in ['database', 'db', 'postgresql', 'mysql', 'mongodb', 'sql']):
            db_name = "Database"
            if 'postgresql' in asset.description.lower():
                db_name = "PostgreSQL Database"
            elif 'mysql' in asset.description.lower():
                db_name = "MySQL Database"
            elif 'mongodb' in asset.description.lower():
                db_name = "MongoDB Database"

            data_store = DataStore(
                name=db_name,
                description="Primary data storage",
                trust_level=TrustLevel.HIGH_TRUST,
                store_type="database",
                isEncrypted='encrypt' in asset.description.lower(),
                hasAccessControl=True,
                stores_pii=asset.data_sensitivity in ['high', 'critical'],
                stores_credentials='password' in asset.description.lower() or 'credential' in asset.description.lower(),
                data_classification=DataClassification.CONFIDENTIAL if asset.data_sensitivity in ['high', 'critical'] else DataClassification.INTERNAL
            )
            dfd.data_stores.append(data_store)

            # Data flow: App -> Database
            app_to_db_flow = DataFlow(
                name="Application Queries",
                description="Database queries from application",
                source_id=app_process.id,
                destination_id=data_store.id,
                data_description="SQL queries and responses",
                data_classification=data_store.data_classification,
                carries_pii=data_store.stores_pii,
                carries_credentials=False,
                protocol=TransportProtocol.SQL,
                isEncrypted='ssl' in asset.description.lower() or 'tls' in asset.description.lower(),
                authentication=AuthenticationMethod.BASIC
            )
            dfd.data_flows.append(app_to_db_flow)

        # 4. Create data flow: User -> Application
        protocol = TransportProtocol.HTTPS if asset.internet_facing and 'https' in asset.description.lower() else TransportProtocol.HTTP

        user_to_app_flow = DataFlow(
            name="User Requests",
            description="HTTP requests from users",
            source_id=user_entity.id,
            destination_id=app_process.id,
            data_description="User input, credentials, session data",
            data_classification=DataClassification.CONFIDENTIAL if asset.data_sensitivity in ['high', 'critical'] else DataClassification.INTERNAL,
            carries_pii=asset.data_sensitivity in ['high', 'critical'],
            carries_credentials='login' in asset.description.lower() or 'password' in asset.description.lower(),
            carries_session_tokens='jwt' in asset.description.lower() or 'token' in asset.description.lower(),
            protocol=protocol,
            isEncrypted=protocol == TransportProtocol.HTTPS,
            authentication=AuthenticationMethod.JWT if 'jwt' in asset.description.lower() else AuthenticationMethod.BASIC if app_process.implementsAuthentication else AuthenticationMethod.NONE
        )
        dfd.data_flows.append(user_to_app_flow)

        # 5. Create trust boundaries
        if asset.internet_facing:
            # Internet -> Internal boundary
            internet_boundary = TrustBoundary(
                name="Internet -> Internal Network",
                description="Boundary between internet and internal network",
                from_trust_level=TrustLevel.UNTRUSTED,
                to_trust_level=TrustLevel.MEDIUM_TRUST,
                component_ids=[user_entity.id],
                has_firewall=True,
                has_waf='waf' in asset.description.lower(),
                requires_authentication=app_process.implementsAuthentication
            )
            dfd.trust_boundaries.append(internet_boundary)

        # Internal -> Database boundary
        if dfd.data_stores:
            db_boundary = TrustBoundary(
                name="Application -> Database",
                description="Boundary between application and database tier",
                from_trust_level=TrustLevel.MEDIUM_TRUST,
                to_trust_level=TrustLevel.HIGH_TRUST,
                component_ids=[app_process.id],
                has_firewall=True,
                requires_authentication=True
            )
            dfd.trust_boundaries.append(db_boundary)

        return dfd

    def generate_mermaid_dfd(self, dfd: DataFlowDiagram, vulnerabilities=None) -> str:
        """
        Generate Mermaid diagram code for the DFD.
        This creates a visual representation of the architecture with vulnerabilities highlighted.

        Args:
            dfd: DataFlowDiagram to visualize
            vulnerabilities: Optional list of vulnerabilities to highlight on diagram
        """
        try:
            mermaid_code = "graph TD\n"

            # Add external entities (no special chars in labels)
            for entity in dfd.external_entities:
                icon = "USER" if entity.entity_type == "user" else "EXTERNAL"
                # Escape special characters and use quotes
                safe_name = entity.name.replace('"', "'").replace('\n', ' ').replace('|', '/')
                node_id = entity.id.hex[:8]
                mermaid_code += f'    {node_id}["{icon} - {safe_name}"]\n'

            # Add processes
            for process in dfd.processes:
                icon = "AUTH" if process.implementsAuthentication else "PROCESS"
                safe_name = process.name.replace('"', "'").replace('\n', ' ').replace('|', '/')
                node_id = process.id.hex[:8]
                mermaid_code += f'    {node_id}["{icon} - {safe_name}"]\n'

            # Add data stores
            for store in dfd.data_stores:
                icon = "ENCRYPTED DB" if store.isEncrypted else "DATABASE"
                safe_name = store.name.replace('"', "'").replace('\n', ' ').replace('|', '/')
                node_id = store.id.hex[:8]
                mermaid_code += f'    {node_id}[("{icon} - {safe_name}")]\n'

            # Add data flows - SIMPLE VERSION WITHOUT COMPLEX LOGIC
            for flow in dfd.data_flows:
                arrow = "==>" if flow.isEncrypted else "-->"
                label = f"{flow.protocol.value}"
                if flow.carries_credentials:
                    label += " (creds)"
                if flow.carries_pii:
                    label += " (PII)"

                mermaid_code += f"    {flow.source_id.hex[:8]} {arrow}|{label}| {flow.destination_id.hex[:8]}\n"

            # Add vulnerabilities - show TOP 10 for better visibility
            if vulnerabilities:
                # Sort by severity and take top 10 (more than 3, but not overwhelming)
                top_vulns = sorted(
                    vulnerabilities,
                    key=lambda v: {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}.get(v.severity.value, 0),
                    reverse=True
                )[:10]

                if top_vulns:
                    mermaid_code += "\n    %% Vulnerabilities\n"
                    for i, vuln in enumerate(top_vulns):
                        vuln_id = f"vuln{i}"

                        # NO TRUNCATION - show full title
                        title_clean = vuln.title.replace('"', "'").replace('[', '(').replace(']', ')')

                        # Severity indicator
                        if vuln.severity.value == 'critical':
                            vuln_label = f"[CRITICAL] {title_clean}"
                        elif vuln.severity.value == 'high':
                            vuln_label = f"[HIGH] {title_clean}"
                        else:
                            vuln_label = f"[{vuln.severity.value.upper()}] {title_clean}"

                        mermaid_code += f'    {vuln_id}["{vuln_label}"]\n'

                        # Connect to process (cycle through if more vulns than processes)
                        if dfd.processes:
                            process_idx = i % len(dfd.processes)
                            mermaid_code += f"    {dfd.processes[process_idx].id.hex[:8]} -.-> {vuln_id}\n"

            # Style critical components
            for entity in dfd.external_entities:
                if entity.can_be_malicious:
                    mermaid_code += f"    style {entity.id.hex[:8]} fill:#ff4444,stroke:#ff4444,color:#fff\n"

            for flow in dfd.data_flows:
                if not flow.isEncrypted and flow.carries_pii:
                    mermaid_code += f"    linkStyle {dfd.data_flows.index(flow)} stroke:#ff4444,stroke-width:3px\n"

            # Style vulnerability nodes by severity (top 10)
            if vulnerabilities and top_vulns:
                for i, vuln in enumerate(top_vulns):
                    vuln_id = f"vuln{i}"
                    if vuln.severity.value == 'critical':
                        mermaid_code += f"    style {vuln_id} fill:#ff0000,stroke:#ff0000,color:#fff\n"
                    elif vuln.severity.value == 'high':
                        mermaid_code += f"    style {vuln_id} fill:#ff6600,stroke:#ff6600,color:#fff\n"
                    else:
                        mermaid_code += f"    style {vuln_id} fill:#ffcc00,stroke:#333,color:#000\n"

            logger.warning("✅ Generated Enhanced Mermaid DFD with vulnerabilities")
            logger.warning(f"📊 Mermaid code (first 500 chars):\n{mermaid_code[:500]}")
            logger.warning(f"📊 Mermaid code (last 200 chars):\n{mermaid_code[-200:]}")
            return mermaid_code

        except Exception as e:
            logger.error(f"❌ ❌ ❌ Mermaid DFD generation CRASHED: {e}")
            import traceback
            logger.error(f"Mermaid traceback:\n{traceback.format_exc()}")
            # Return a simple fallback diagram
            fallback = """graph TD
    A["System Analysis"]
    B["Unable to generate DFD"]
    A --> B
"""
            logger.warning(f"Returning fallback diagram:\n{fallback}")
            return fallback

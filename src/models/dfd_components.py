"""
Data Flow Diagram (DFD) Components
Based on OWASP pytm methodology for structured threat modeling
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Literal
from uuid import UUID, uuid4
from enum import Enum


class TrustLevel(str, Enum):
    """Trust levels for boundaries and components"""
    UNTRUSTED = "untrusted"          # Internet, public networks
    LOW_TRUST = "low_trust"           # DMZ, semi-trusted zones
    MEDIUM_TRUST = "medium_trust"     # Internal networks
    HIGH_TRUST = "high_trust"         # Secure zones, databases
    CRITICAL = "critical"             # Core infrastructure


class DataClassification(str, Enum):
    """Data sensitivity classification"""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    TOP_SECRET = "top_secret"


class TransportProtocol(str, Enum):
    """Network transport protocols"""
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    SSH = "SSH"
    FTP = "FTP"
    SFTP = "SFTP"
    SMTP = "SMTP"
    SQL = "SQL"
    WEBSOCKET = "WebSocket"
    GRPC = "gRPC"
    MQTT = "MQTT"
    CUSTOM = "Custom"


class AuthenticationMethod(str, Enum):
    """Authentication mechanisms"""
    NONE = "none"
    BASIC = "basic"
    TOKEN = "token"
    JWT = "jwt"
    OAUTH = "oauth"
    SAML = "saml"
    CERTIFICATE = "certificate"
    MULTI_FACTOR = "multi_factor"


class DFDComponent(BaseModel):
    """Base class for all DFD components"""
    id: UUID = Field(default_factory=uuid4)
    name: str
    description: Optional[str] = None
    trust_level: TrustLevel = TrustLevel.MEDIUM_TRUST
    notes: Optional[str] = None


class ExternalEntity(DFDComponent):
    """
    External entity interacting with the system.
    Examples: User, External API, Partner System, Attacker
    """
    entity_type: Literal["user", "system", "actor", "attacker"] = "user"
    is_authenticated: bool = False
    can_be_malicious: bool = True  # Assume external entities can be malicious


class Process(DFDComponent):
    """
    A process that transforms or processes data.
    Examples: Web Server, Application Logic, Authentication Service
    """
    runs_as: Optional[str] = None  # User/service account it runs as
    implementsAuthentication: bool = False
    implementsAuthorization: bool = False
    implementsNonce: bool = False
    checksDestination: bool = False
    sanitizesInput: bool = False
    encodesOutput: bool = False
    handlesResourceConsumption: bool = False
    implementsCryptography: bool = False
    validatesHeaders: bool = False

    # What this process does
    processes_pii: bool = False
    processes_credentials: bool = False
    processes_financial_data: bool = False

    # Technology stack
    technology: Optional[str] = None
    programming_language: Optional[str] = None
    framework: Optional[str] = None


class DataStore(DFDComponent):
    """
    Storage of data at rest.
    Examples: Database, File System, Cache, S3 Bucket
    """
    store_type: Literal["database", "file_system", "cache", "cloud_storage", "log"] = "database"

    # Security controls
    isEncrypted: bool = False
    hasAccessControl: bool = False
    hasBackup: bool = False
    isResilient: bool = False

    # Data characteristics
    stores_pii: bool = False
    stores_credentials: bool = False
    stores_logs: bool = False
    data_classification: DataClassification = DataClassification.INTERNAL

    # Storage details
    technology: Optional[str] = None  # PostgreSQL, MongoDB, S3, Redis, etc.


class DataFlow(DFDComponent):
    """
    Flow of data between components.
    Examples: HTTP Request, Database Query, API Call
    """
    source_id: UUID
    destination_id: UUID

    # What data is flowing
    data_description: str
    data_classification: DataClassification = DataClassification.INTERNAL
    carries_pii: bool = False
    carries_credentials: bool = False
    carries_session_tokens: bool = False

    # Transport security
    protocol: TransportProtocol = TransportProtocol.HTTP
    isEncrypted: bool = False
    authentication: AuthenticationMethod = AuthenticationMethod.NONE

    # Security controls
    isFiltered: bool = False          # Input validation/sanitization
    implementsAuthenticationScheme: bool = False
    implementsNonce: bool = False
    usesVPN: bool = False
    usesSessionTokens: bool = False


class TrustBoundary(BaseModel):
    """
    Boundary between different trust zones.
    Examples: Internet -> DMZ, DMZ -> Internal Network, Internal -> Database
    """
    id: UUID = Field(default_factory=uuid4)
    name: str
    description: Optional[str] = None

    from_trust_level: TrustLevel
    to_trust_level: TrustLevel

    # Components within this boundary
    component_ids: List[UUID] = Field(default_factory=list)

    # Security controls at boundary
    has_firewall: bool = False
    has_ids_ips: bool = False
    has_waf: bool = False
    requires_authentication: bool = False


class ThreatPattern(BaseModel):
    """
    Pre-defined threat pattern based on component types and configurations.
    Based on STRIDE methodology adapted to OWASP.
    """
    id: UUID = Field(default_factory=uuid4)
    name: str
    description: str

    # STRIDE category (still useful for threat generation)
    stride_category: Literal[
        "spoofing",
        "tampering",
        "repudiation",
        "information_disclosure",
        "denial_of_service",
        "elevation_of_privilege"
    ]

    # Maps to OWASP Top 10
    owasp_category: str
    cwe_id: str

    # When this threat applies
    applies_to_component: Literal["process", "datastore", "dataflow", "external_entity"]

    # Conditions for this threat
    conditions: List[str] = Field(default_factory=list)

    # Threat details
    attack_vector: str
    impact: str
    likelihood: Literal["low", "medium", "high"]
    severity: Literal["low", "medium", "high", "critical"]

    # Mitigations
    mitigations: List[str] = Field(default_factory=list)


class DataFlowDiagram(BaseModel):
    """
    Complete Data Flow Diagram representing the system architecture
    """
    id: UUID = Field(default_factory=uuid4)
    name: str
    description: str

    # Components
    external_entities: List[ExternalEntity] = Field(default_factory=list)
    processes: List[Process] = Field(default_factory=list)
    data_stores: List[DataStore] = Field(default_factory=list)
    data_flows: List[DataFlow] = Field(default_factory=list)
    trust_boundaries: List[TrustBoundary] = Field(default_factory=list)

    # Metadata
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    def get_component_by_id(self, component_id: UUID):
        """Get any component by its ID"""
        for entity in self.external_entities:
            if entity.id == component_id:
                return entity
        for process in self.processes:
            if process.id == component_id:
                return process
        for store in self.data_stores:
            if store.id == component_id:
                return store
        return None

    def get_flows_crossing_boundaries(self) -> List[tuple[DataFlow, TrustBoundary]]:
        """
        Find all data flows that cross trust boundaries.
        This is where most security issues occur.
        """
        crossing_flows = []

        for flow in self.data_flows:
            source = self.get_component_by_id(flow.source_id)
            dest = self.get_component_by_id(flow.destination_id)

            if source and dest and source.trust_level != dest.trust_level:
                # Flow crosses trust boundary
                for boundary in self.trust_boundaries:
                    if (source.trust_level == boundary.from_trust_level and
                        dest.trust_level == boundary.to_trust_level):
                        crossing_flows.append((flow, boundary))

        return crossing_flows

    def get_sensitive_data_flows(self) -> List[DataFlow]:
        """Get all flows carrying sensitive data"""
        return [
            flow for flow in self.data_flows
            if flow.carries_pii or
               flow.carries_credentials or
               flow.data_classification in [DataClassification.RESTRICTED, DataClassification.TOP_SECRET]
        ]

    def get_unencrypted_sensitive_flows(self) -> List[DataFlow]:
        """Get sensitive data flows that are not encrypted"""
        return [
            flow for flow in self.get_sensitive_data_flows()
            if not flow.isEncrypted
        ]

    def get_unauthenticated_flows(self) -> List[DataFlow]:
        """Get data flows without authentication"""
        return [
            flow for flow in self.data_flows
            if flow.authentication == AuthenticationMethod.NONE
        ]

    def validate_security_controls(self) -> List[str]:
        """
        Validate security controls and return list of issues.
        This mimics pytm's automatic threat generation.
        """
        issues = []

        # Check for unencrypted sensitive data
        unencrypted = self.get_unencrypted_sensitive_flows()
        if unencrypted:
            issues.append(f"Found {len(unencrypted)} sensitive data flows without encryption")

        # Check for unauthenticated processes handling sensitive data
        for process in self.processes:
            if (process.processes_pii or process.processes_credentials) and not process.implementsAuthentication:
                issues.append(f"Process '{process.name}' handles sensitive data without authentication")

        # Check for unencrypted data stores
        for store in self.data_stores:
            if store.stores_pii or store.stores_credentials:
                if not store.isEncrypted:
                    issues.append(f"DataStore '{store.name}' contains sensitive data but is not encrypted")

        # Check for missing input validation
        for process in self.processes:
            if not process.sanitizesInput:
                issues.append(f"Process '{process.name}' may be vulnerable to injection attacks (no input sanitization)")

        # Check for trust boundary violations
        crossing = self.get_flows_crossing_boundaries()
        for flow, boundary in crossing:
            if not flow.isEncrypted and flow.carries_pii:
                issues.append(f"Data flow '{flow.name}' crosses trust boundary without encryption")

        return issues

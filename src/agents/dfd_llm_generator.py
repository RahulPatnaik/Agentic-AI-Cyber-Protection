"""
DFD LLM Generator
Uses Cerebras (underutilized, fast, free) to generate intelligent DFDs
"""

import json
import asyncio
from typing import Dict, Optional, List
import structlog
import os
from dotenv import load_dotenv

# Try to import Cerebras, fallback if not available
try:
    from cerebras.cloud.sdk import AsyncCerebras
    CEREBRAS_AVAILABLE = True
except ImportError:
    CEREBRAS_AVAILABLE = False
    AsyncCerebras = None

from src.models.dfd_components import (
    DataFlowDiagram,
    ExternalEntity,
    Process,
    DataStore,
    DataFlow,
    TrustLevel,
    TransportProtocol,
    AuthenticationMethod,
    DataClassification
)
from uuid import uuid4

# Load environment variables
load_dotenv()

logger = structlog.get_logger()


class DFDLLMGenerator:
    """Generate Data Flow Diagrams using Cerebras LLM"""

    def __init__(self):
        # Initialize Cerebras client if available
        self.client = None

        if not CEREBRAS_AVAILABLE:
            logger.warning("Cerebras SDK not available, DFD generation will use fallback")
        else:
            api_key = os.getenv("CEREBRAS_API_KEY")
            if not api_key:
                logger.warning("CEREBRAS_API_KEY not found, DFD LLM generation will use fallback")
            else:
                try:
                    self.client = AsyncCerebras(api_key=api_key)
                    logger.info("Initialized Cerebras for DFD generation")
                except Exception as e:
                    logger.warning(f"Failed to initialize Cerebras: {e}")
                    self.client = None

        self.dfd_cache = {}  # Cache generated DFDs

    async def generate_dfd(self, description: str, use_cache: bool = True) -> Dict:
        """Generate DFD specification from description using Cerebras"""

        # Check cache first
        cache_key = hash(description[:200])  # Use first 200 chars as key
        if use_cache and cache_key in self.dfd_cache:
            logger.info("Using cached DFD")
            return self.dfd_cache[cache_key]

        prompt = f"""Analyze this system and create a detailed Data Flow Diagram specification.

System Description: {description}

Generate a realistic multi-tier architecture. Return ONLY valid JSON with this exact structure:

IMPORTANT:
- For entity "type", use ONLY: "user" (for people), "system" (for external services/APIs), "actor" (for admins), or "attacker" (for threats)
- For data_stores "type", use ONLY: "database", "file_system", "cache", "cloud_storage", or "log"
- For data_flows "protocol", use: "HTTPS", "HTTP", "SQL", "SSH", "FTP", "SFTP", "SMTP", "WebSocket", "gRPC", or "REST" (NOT "TCP")

{{
  "external_entities": [
    {{"name": "End Users", "type": "user", "trust": "untrusted", "can_be_malicious": true}},
    {{"name": "Admin Portal", "type": "actor", "trust": "medium", "can_be_malicious": false}},
    {{"name": "Third Party API", "type": "system", "trust": "low", "can_be_malicious": false}}
  ],
  "processes": [
    {{"name": "React Frontend", "tech": "React", "trust": "low", "handles_auth": false, "sanitizes_input": true}},
    {{"name": "API Gateway", "tech": "Kong/Nginx", "trust": "medium", "handles_auth": true, "sanitizes_input": true}},
    {{"name": "Auth Service", "tech": "OAuth2/JWT", "trust": "high", "handles_auth": true, "sanitizes_input": true}},
    {{"name": "Business Logic", "tech": "Node.js/Python", "trust": "medium", "handles_auth": false, "sanitizes_input": false}}
  ],
  "data_stores": [
    {{"name": "PostgreSQL", "type": "database", "encrypted": true, "stores_pii": true}},
    {{"name": "Redis Cache", "type": "cache", "encrypted": false, "stores_pii": false}}
  ],
  "data_flows": [
    {{"from": "End Users", "to": "React Frontend", "protocol": "HTTPS", "carries_pii": false}},
    {{"from": "React Frontend", "to": "API Gateway", "protocol": "REST", "carries_pii": true}},
    {{"from": "API Gateway", "to": "Auth Service", "protocol": "REST", "carries_pii": true}},
    {{"from": "API Gateway", "to": "Business Logic", "protocol": "REST", "carries_pii": true}},
    {{"from": "Business Logic", "to": "PostgreSQL", "protocol": "SQL", "carries_pii": true}},
    {{"from": "Business Logic", "to": "Redis Cache", "protocol": "HTTPS", "carries_pii": false}}
  ],
  "trust_boundaries": [
    {{"name": "Internet-DMZ", "crosses": ["End Users", "React Frontend"]}},
    {{"name": "DMZ-Internal", "crosses": ["API Gateway", "Business Logic"]}}
  ]
}}

Based on the description, include:
- Relevant external entities (users, third-party APIs)
- Appropriate processes/services based on mentioned technologies
- Data stores (databases, caches, queues) if mentioned
- Realistic data flows between components
- Trust boundaries between network zones

Return ONLY the JSON, no explanations."""

        try:
            if not self.client:
                logger.warning("Cerebras client not initialized, using default")
                return self._get_default_dfd()

            logger.info("Generating DFD with Cerebras (fast, free tier)")

            # Use Cerebras chat completion API
            response = await self.client.chat.completions.create(
                model="llama3.1-8b",  # Fast model
                messages=[
                    {"role": "system", "content": "You are a system architect that generates detailed Data Flow Diagrams in JSON format."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,  # Lower temp for structured output
                max_tokens=2000
            )

            result = response.choices[0].message.content

            # Extract JSON from response
            json_str = result.strip()
            if json_str.startswith("```json"):
                json_str = json_str[7:]
            if json_str.startswith("```"):
                json_str = json_str[3:]
            if json_str.endswith("```"):
                json_str = json_str[:-3]

            dfd_spec = json.loads(json_str.strip())

            # Validate structure
            self._validate_dfd_spec(dfd_spec)

            # Cache result
            if use_cache:
                self.dfd_cache[cache_key] = dfd_spec

            logger.info(
                "DFD generated successfully",
                entities=len(dfd_spec.get('external_entities', [])),
                processes=len(dfd_spec.get('processes', [])),
                stores=len(dfd_spec.get('data_stores', [])),
                flows=len(dfd_spec.get('data_flows', []))
            )

            return dfd_spec

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Cerebras response as JSON: {e}")
            # Return a sensible default
            return self._get_default_dfd()
        except Exception as e:
            logger.error(f"Cerebras DFD generation failed: {e}")
            return self._get_default_dfd()

    def _validate_dfd_spec(self, spec: Dict) -> bool:
        """Validate DFD specification has required components"""
        required = ['external_entities', 'processes', 'data_stores', 'data_flows']
        for field in required:
            if field not in spec or not spec[field]:
                raise ValueError(f"Missing or empty required field: {field}")

        # Ensure at least basic components exist
        if len(spec['processes']) < 2:
            raise ValueError("DFD must have at least 2 processes")

        return True

    def _get_default_dfd(self) -> Dict:
        """Return a sensible default DFD if generation fails"""
        return {
            "external_entities": [
                {"name": "End Users", "type": "user", "trust": "untrusted", "can_be_malicious": True},
                {"name": "Admin Users", "type": "actor", "trust": "medium", "can_be_malicious": False},
                {"name": "External APIs", "type": "system", "trust": "low", "can_be_malicious": False}
            ],
            "processes": [
                {"name": "Web Frontend", "tech": "React", "trust": "low", "handles_auth": False, "sanitizes_input": True},
                {"name": "API Gateway", "tech": "Express", "trust": "medium", "handles_auth": True, "sanitizes_input": True},
                {"name": "Business Logic", "tech": "Python", "trust": "medium", "handles_auth": False, "sanitizes_input": False},
                {"name": "Auth Service", "tech": "OAuth2", "trust": "high", "handles_auth": True, "sanitizes_input": True}
            ],
            "data_stores": [
                {"name": "PostgreSQL", "type": "database", "encrypted": True, "stores_pii": True},
                {"name": "Redis Cache", "type": "cache", "encrypted": False, "stores_pii": False}
            ],
            "data_flows": [
                {"from": "End Users", "to": "Web Frontend", "protocol": "HTTPS", "carries_pii": False},
                {"from": "Web Frontend", "to": "API Gateway", "protocol": "REST", "carries_pii": False},
                {"from": "API Gateway", "to": "Business Logic", "protocol": "REST", "carries_pii": True},
                {"from": "Business Logic", "to": "PostgreSQL", "protocol": "SQL", "carries_pii": True}
            ],
            "trust_boundaries": [
                {"name": "Internet-DMZ", "crosses": ["End Users", "Web Frontend"]},
                {"name": "DMZ-Internal", "crosses": ["API Gateway", "Business Logic"]}
            ]
        }

    def convert_to_dfd_objects(self, spec: Dict) -> DataFlowDiagram:
        """Convert JSON spec to actual DFD objects"""

        dfd = DataFlowDiagram(
            name="System Architecture",
            description="LLM-generated architecture"
        )

        # Track IDs for linking
        entity_ids = {}
        process_ids = {}
        store_ids = {}

        # Create external entities
        for entity_spec in spec.get('external_entities', []):
            # Map LLM entity types to valid enum values
            entity_type = self._map_entity_type(entity_spec.get('type', 'user'))

            entity = ExternalEntity(
                name=entity_spec['name'],
                description=f"{entity_spec.get('type', 'external')} entity",
                entity_type=entity_type,
                trust_level=self._map_trust_level(entity_spec.get('trust', 'untrusted')),
                is_authenticated=entity_spec.get('trust') != 'untrusted',
                can_be_malicious=entity_spec.get('can_be_malicious', True)
            )
            dfd.external_entities.append(entity)
            entity_ids[entity_spec['name']] = entity.id

        # Create processes
        for proc_spec in spec.get('processes', []):
            process = Process(
                name=proc_spec['name'],
                description=f"Service using {proc_spec.get('tech', 'unknown')}",
                trust_level=self._map_trust_level(proc_spec.get('trust', 'medium')),
                implementsAuthentication=proc_spec.get('handles_auth', False),
                implementsAuthorization=proc_spec.get('handles_auth', False),
                sanitizesInput=proc_spec.get('sanitizes_input', False),
                encodesOutput=proc_spec.get('sanitizes_input', False),
                processes_pii='Logic' in proc_spec['name'] or 'Auth' in proc_spec['name'],
                processes_credentials='Auth' in proc_spec['name'],
                technology=proc_spec.get('tech'),
                programming_language=self._infer_language(proc_spec.get('tech', ''))
            )
            dfd.processes.append(process)
            process_ids[proc_spec['name']] = process.id

        # Create data stores
        for store_spec in spec.get('data_stores', []):
            # Map LLM store types to valid enum values
            store_type = self._map_store_type(store_spec.get('type', 'database'))

            store = DataStore(
                name=store_spec['name'],
                description=f"{store_spec.get('type', store_type)} storage",
                trust_level=TrustLevel.HIGH_TRUST,
                store_type=store_type,  # Use mapped type
                isEncrypted=store_spec.get('encrypted', False),
                hasAccessControl=True,
                stores_pii=store_spec.get('stores_pii', False),
                stores_credentials='auth' in store_spec['name'].lower(),
                data_classification=DataClassification.CONFIDENTIAL if store_spec.get('stores_pii') else DataClassification.INTERNAL
            )
            dfd.data_stores.append(store)
            store_ids[store_spec['name']] = store.id

        # Create data flows
        for flow_spec in spec.get('data_flows', []):
            # Find source and destination IDs
            source_id = (entity_ids.get(flow_spec['from']) or
                        process_ids.get(flow_spec['from']) or
                        store_ids.get(flow_spec['from']))

            dest_id = (entity_ids.get(flow_spec['to']) or
                      process_ids.get(flow_spec['to']) or
                      store_ids.get(flow_spec['to']))

            if source_id and dest_id:
                flow = DataFlow(
                    name=f"{flow_spec['from']} to {flow_spec['to']}",
                    description=f"Data flow via {flow_spec['protocol']}",
                    source_id=source_id,
                    destination_id=dest_id,
                    data_description="Application data",
                    data_classification=DataClassification.CONFIDENTIAL if flow_spec.get('carries_pii') else DataClassification.INTERNAL,
                    carries_pii=flow_spec.get('carries_pii', False),
                    carries_credentials='auth' in flow_spec['from'].lower() or 'auth' in flow_spec['to'].lower(),
                    protocol=self._map_protocol(flow_spec['protocol']),
                    isEncrypted=flow_spec['protocol'] in ['HTTPS', 'TLS', 'SSL'],
                    authentication=AuthenticationMethod.OAUTH if 'auth' in flow_spec['to'].lower() else AuthenticationMethod.NONE
                )
                dfd.data_flows.append(flow)

        return dfd

    def _map_entity_type(self, type_str: str) -> str:
        """Map LLM entity type to valid enum values"""
        type_lower = type_str.lower()

        # Map various LLM outputs to valid entity types
        # Check for attacker-related terms first (before checking for 'user')
        if 'attack' in type_lower or 'malicious' in type_lower or 'threat' in type_lower:
            return 'attacker'
        elif 'user' in type_lower or 'customer' in type_lower or 'client' in type_lower:
            return 'user'
        elif 'api' in type_lower or 'service' in type_lower or 'third' in type_lower or 'external' in type_lower:
            return 'system'
        elif 'admin' in type_lower or 'operator' in type_lower:
            return 'actor'
        else:
            # Default to system for unknown types
            return 'system'

    def _map_trust_level(self, trust_str: str) -> TrustLevel:
        """Map string trust level to enum"""
        mapping = {
            'untrusted': TrustLevel.UNTRUSTED,
            'low': TrustLevel.LOW_TRUST,
            'medium': TrustLevel.MEDIUM_TRUST,
            'high': TrustLevel.HIGH_TRUST
        }
        return mapping.get(trust_str, TrustLevel.MEDIUM_TRUST)

    def _map_protocol(self, protocol_str: str) -> TransportProtocol:
        """Map string protocol to enum"""
        mapping = {
            'HTTPS': TransportProtocol.HTTPS,
            'HTTP': TransportProtocol.HTTP,
            'REST': TransportProtocol.HTTPS,
            'SQL': TransportProtocol.SQL,
            'SSH': TransportProtocol.SSH,
            'FTP': TransportProtocol.FTP,
            'SFTP': TransportProtocol.SFTP,
            'SMTP': TransportProtocol.SMTP,
            'WebSocket': TransportProtocol.WEBSOCKET,
            'gRPC': TransportProtocol.GRPC
        }
        # TCP is not in the enum, default to HTTPS for TCP connections
        if protocol_str.upper() == 'TCP':
            return TransportProtocol.HTTPS
        return mapping.get(protocol_str, TransportProtocol.HTTPS)

    def _map_store_type(self, type_str: str) -> str:
        """Map LLM store type to valid enum values"""
        type_lower = type_str.lower()

        # Map various storage types to valid enum values
        if 'database' in type_lower or 'db' in type_lower or 'sql' in type_lower:
            return 'database'
        elif 'file' in type_lower or 'disk' in type_lower or 'folder' in type_lower:
            return 'file_system'
        elif 'cache' in type_lower or 'redis' in type_lower or 'memcache' in type_lower:
            return 'cache'
        elif 'cloud' in type_lower or 's3' in type_lower or 'blob' in type_lower or 'bucket' in type_lower:
            return 'cloud_storage'
        elif 'log' in type_lower or 'audit' in type_lower:
            return 'log'
        elif 'queue' in type_lower or 'message' in type_lower or 'kafka' in type_lower or 'rabbit' in type_lower:
            # Queues are closest to cache in terms of temporary storage
            return 'cache'
        else:
            # Default to database for unknown types
            return 'database'

    def _infer_language(self, tech: str) -> str:
        """Infer programming language from technology"""
        tech_lower = tech.lower()
        if 'react' in tech_lower or 'vue' in tech_lower or 'angular' in tech_lower:
            return 'JavaScript'
        elif 'django' in tech_lower or 'flask' in tech_lower or 'fastapi' in tech_lower:
            return 'Python'
        elif 'express' in tech_lower or 'node' in tech_lower:
            return 'Node.js'
        elif 'spring' in tech_lower:
            return 'Java'
        elif '.net' in tech_lower or 'asp' in tech_lower:
            return 'C#'
        else:
            return 'Unknown'


# Export singleton instance
dfd_llm_generator = DFDLLMGenerator()
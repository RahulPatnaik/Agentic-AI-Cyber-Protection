"""
Network and Packet Models
Data structures for network traffic and packet analysis
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime


class PacketFeatures(BaseModel):
    """
    ML features extracted from network packets.
    Used by Guardian agent for threat detection.
    """
    # Packet-level features
    frame_type: str = Field(..., description="Management, Control, or Data")
    src_mac: str
    dst_mac: str
    packet_size: int = Field(..., description="Packet size in bytes")
    rssi: Optional[float] = Field(None, description="Received Signal Strength Indicator")

    # Protocol features
    protocol: str = Field(..., description="Protocol (TCP, UDP, ARP, etc.)")
    port_src: Optional[int] = None
    port_dst: Optional[int] = None

    # Timing features
    timestamp: datetime
    inter_arrival_time: Optional[float] = Field(None, description="Time since last packet (ms)")

    # Flow-level features (computed over time window)
    packet_rate: Optional[float] = Field(None, description="Packets per second")
    byte_rate: Optional[float] = Field(None, description="Bytes per second")
    flow_duration: Optional[float] = Field(None, description="Flow duration in seconds")

    # Statistical features
    mean_packet_size: Optional[float] = None
    std_packet_size: Optional[float] = None
    packet_size_entropy: Optional[float] = None
    dst_address_entropy: Optional[float] = None

    # Behavioral features
    unique_src_ips: Optional[int] = None
    unique_dst_ips: Optional[int] = None
    unique_src_ports: Optional[int] = None
    unique_dst_ports: Optional[int] = None

    # Raw packet data (for evidence)
    raw_packet_id: Optional[str] = None

    def to_feature_vector(self) -> List[float]:
        """
        Convert to numeric feature vector for ML models.
        Returns list of floats suitable for sklearn models.
        """
        return [
            float(self.packet_size),
            self.rssi or 0.0,
            self.inter_arrival_time or 0.0,
            self.packet_rate or 0.0,
            self.byte_rate or 0.0,
            self.flow_duration or 0.0,
            self.mean_packet_size or 0.0,
            self.std_packet_size or 0.0,
            self.packet_size_entropy or 0.0,
            self.dst_address_entropy or 0.0,
            float(self.unique_src_ips or 0),
            float(self.unique_dst_ips or 0),
            float(self.unique_src_ports or 0),
            float(self.unique_dst_ports or 0),
        ]

    def to_embedding(self) -> List[float]:
        """Convert to embedding vector for ChromaDB similarity search"""
        return self.to_feature_vector()

    model_config = {
        "json_schema_extra": {
            "example": {
                "frame_type": "Data",
                "src_mac": "00:11:22:33:44:55",
                "dst_mac": "AA:BB:CC:DD:EE:FF",
                "packet_size": 1500,
                "rssi": -45.5,
                "protocol": "TCP",
                "port_src": 443,
                "port_dst": 52341,
                "timestamp": "2026-01-23T10:30:45Z",
                "packet_rate": 100.5,
                "byte_rate": 150000.0
            }
        }
    }


class Connection(BaseModel):
    """Network connection/flow"""
    src_device: str = Field(..., description="Source MAC or IP")
    dst_device: str = Field(..., description="Destination MAC or IP")
    protocol: str
    start_time: datetime
    end_time: Optional[datetime] = None
    packet_count: int = 0
    byte_count: int = 0
    is_suspicious: bool = False


class NetworkState(BaseModel):
    """Current network state snapshot"""
    total_devices: int
    active_connections: int
    network_type: str = Field(..., description="Home, Enterprise, Public, etc.")
    security_level: str = Field(..., description="WPA2, WPA3, Open, etc.")
    threat_level: str = Field(..., description="Current overall threat level")
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class PacketCapture(BaseModel):
    """Metadata for a captured packet"""
    packet_id: str
    timestamp: datetime
    interface: str
    packet_size: int
    protocol: str
    src_mac: str
    dst_mac: str
    pcap_file: Optional[str] = None
    is_malicious: Optional[bool] = None


class ThreatSignature(BaseModel):
    """Known threat signature for database storage"""
    signature_id: str
    threat_type: str
    indicators: Dict[str, Any]
    severity: str
    description: str
    first_seen: datetime
    last_seen: datetime
    occurrence_count: int = 1

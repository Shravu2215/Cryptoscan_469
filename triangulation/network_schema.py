"""
Network Observation Schema & Data Model for CryptoScan Triangulation.
Represents cryptographic metadata captured from network traffic (TLS, SSH, IPsec).
"""

from dataclasses import dataclass, field, asdict
import uuid
from typing import Optional, List, Dict, Any
from runtime.normalize import normalize_algorithm, extract_network_algorithms


QUANTUM_VULNERABLE_ALGOS = {
    "RSA",
    "ECDSA",
    "ECDH",
    "ECDHE",
    "DH",
    "DSA",
    "X25519",
}


@dataclass
class NetworkObservation:
    observation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    capture_id: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    protocol: str = "TLS"  # TLS, SSH, IPsec, other
    protocol_version: str = "TLSv1.3"  # e.g. TLSv1.2, TLSv1.3
    cipher_suite: Optional[str] = None  # e.g. TLS_AES_256_GCM_SHA384
    key_exchange: Optional[str] = None  # e.g. ECDHE, X25519, RSA, X25519MLKEM768
    signature_algorithm: Optional[str] = None  # e.g. sha256WithRSAEncryption
    certificate_key_type: Optional[str] = None  # RSA, EC, etc.
    certificate_key_size: Optional[int] = None
    normalized_algorithms: List[str] = field(default_factory=list)
    quantum_vulnerable: bool = False

    def __post_init__(self):
        if not self.normalized_algorithms:
            self.normalized_algorithms = extract_network_algorithms(
                cipher_suite=self.cipher_suite,
                key_exchange=self.key_exchange,
                signature_algorithm=self.signature_algorithm,
                certificate_key_type=self.certificate_key_type,
            )

        # Check quantum vulnerability against normalized algorithms
        self.quantum_vulnerable = any(
            algo in QUANTUM_VULNERABLE_ALGOS for algo in self.normalized_algorithms
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "NetworkObservation":
        kwargs = {
            "observation_id": data.get("observation_id") or data.get("id") or str(uuid.uuid4()),
            "capture_id": data.get("capture_id") or data.get("captureId"),
            "host": data.get("host"),
            "port": data.get("port"),
            "protocol": data.get("protocol", "TLS"),
            "protocol_version": data.get("protocol_version") or data.get("protocolVersion", "TLSv1.3"),
            "cipher_suite": data.get("cipher_suite") or data.get("cipherSuite"),
            "key_exchange": data.get("key_exchange") or data.get("keyExchange"),
            "signature_algorithm": data.get("signature_algorithm") or data.get("signatureAlgorithm"),
            "certificate_key_type": data.get("certificate_key_type") or data.get("certificateKeyType"),
            "certificate_key_size": data.get("certificate_key_size") or data.get("certificateKeySize"),
        }
        if "normalized_algorithms" in data:
            kwargs["normalized_algorithms"] = data["normalized_algorithms"]
        return cls(**kwargs)

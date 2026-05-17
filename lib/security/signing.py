import os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption, load_der_private_key
)


def generate_signing_keypair() -> tuple[bytes, bytes]:
    """Returns (private_key_der, public_key_raw_bytes)."""
    private_key = Ed25519PrivateKey.generate()
    private_der = private_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
    public_raw = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return private_der, public_raw


def load_signing_keypair(private_key_der: bytes) -> tuple[bytes, bytes]:
    """Derive public key from stored private DER. Returns (private_der, public_raw)."""
    private_key = load_der_private_key(private_key_der, password=None)
    public_raw = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return private_key_der, public_raw


def sign(private_key_der: bytes, message: bytes) -> bytes:
    """Sign message with Ed25519 private key. Returns 64-byte signature."""
    private_key = load_der_private_key(private_key_der, password=None)
    return private_key.sign(message)


def verify(public_key_raw: bytes, message: bytes, signature: bytes) -> bool:
    """Verify Ed25519 signature. Returns False on any failure — never raises."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives.serialization import load_der_public_key
        from cryptography.exceptions import InvalidSignature
        public_key = Ed25519PublicKey.from_public_bytes(public_key_raw)
        public_key.verify(signature, message)
        return True
    except Exception:
        return False


def build_registration_message(file_id: str, port: int, filename: str, size: int, timestamp: int) -> bytes:
    """Canonical signed payload. Must match on both client and server."""
    return f"{file_id}:{port}:{filename}:{size}:{timestamp // 10}".encode()


def save_signing_key(private_key_der: bytes, path: str) -> None:
    """Write private key to disk with restricted permissions."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(private_key_der)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def load_or_generate_keypair(path: str) -> tuple[bytes, bytes]:
    """Load keypair from path or generate and persist a new one."""
    if os.path.exists(path):
        with open(path, "rb") as f:
            private_der = f.read()
        return load_signing_keypair(private_der)
    private_der, public_raw = generate_signing_keypair()
    save_signing_key(private_der, path)
    return private_der, public_raw

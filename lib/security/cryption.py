import os
import base64

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption, load_der_private_key
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Wire format: ephemeral_pubkey (32) | nonce (12) | aesgcm_ciphertext+tag (variable)
_EPH_PUBKEY_LEN = 32
_NONCE_LEN = 12
_HKDF_INFO = b'p2p-file-share-v2'


def generate_keypair() -> tuple[bytes, bytes]:
    """Returns (public_key_raw_32b, private_key_der). Same return order as before."""
    private_key = X25519PrivateKey.generate()
    public_raw = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    private_der = private_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
    return public_raw, private_der


def encrypt(public_key: bytes | str, plaintext: bytes | str) -> bytes | None:
    """
    ECIES: ephemeral X25519 DH + HKDF-SHA256 → AES-256-GCM.
    Per-chunk ephemeral key provides forward secrecy.
    """
    try:
        if isinstance(public_key, str):
            public_key = base64.b64decode(public_key, validate=True)
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()

        server_pub = X25519PublicKey.from_public_bytes(public_key)
        eph_priv = X25519PrivateKey.generate()
        eph_pub_raw = eph_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

        shared = eph_priv.exchange(server_pub)
        aes_key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None, info=_HKDF_INFO
        ).derive(shared)

        nonce = os.urandom(_NONCE_LEN)
        ciphertext_with_tag = AESGCM(aes_key).encrypt(nonce, plaintext, None)

        return eph_pub_raw + nonce + ciphertext_with_tag

    except Exception as exc:
        print(f"Encryption error: {exc}")
        return None


def decrypt(private_key: bytes | str, combined_data: bytes | str) -> bytes | None:
    """Reverse ECIES — mirrors encrypt() exactly."""
    try:
        if isinstance(private_key, str):
            private_key = base64.b64decode(private_key, validate=True)
        if isinstance(combined_data, str):
            combined_data = combined_data.encode()

        eph_pub_raw = combined_data[:_EPH_PUBKEY_LEN]
        nonce = combined_data[_EPH_PUBKEY_LEN: _EPH_PUBKEY_LEN + _NONCE_LEN]
        ciphertext_with_tag = combined_data[_EPH_PUBKEY_LEN + _NONCE_LEN:]

        server_priv = load_der_private_key(private_key, password=None)
        eph_pub = X25519PublicKey.from_public_bytes(eph_pub_raw)

        shared = server_priv.exchange(eph_pub)
        aes_key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None, info=_HKDF_INFO
        ).derive(shared)

        return AESGCM(aes_key).decrypt(nonce, ciphertext_with_tag, None)

    except Exception as exc:
        print(f"Decryption error: {exc}")
        return None

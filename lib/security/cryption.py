import base64
import typing
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from pydantic import ValidationError
from quantcrypt import kem, errors
import lib.utils as utils


kyber = kem.Kyber()
AES_BLOCK_SIZE = AES.block_size
CIPHER_TEXT_LENGTH = 1568


class AESCryption:
    def __init__(self, key: bytes | str):
        self.key = key.encode() if isinstance(key, str) else key

    @staticmethod
    def pad(data: str | bytes) -> bytes:
        pad_len = AES_BLOCK_SIZE - len(data) % AES_BLOCK_SIZE
        padding = chr(pad_len) * pad_len
        return data + padding if isinstance(data, str) else data + bytes(padding, 'utf-8')

    @staticmethod
    def unpad(data: bytes) -> bytes:
        return data[:-data[-1]]

    def encrypt(self, raw: bytes | str) -> bytes:
        if isinstance(raw, str):
            raw = base64.b64decode(raw, validate=True)

        raw = self.pad(raw)
        iv = get_random_bytes(AES_BLOCK_SIZE)
        cipher = AES.new(self.key, AES.MODE_GCM, iv)
        encrypted = cipher.encrypt(raw)
        return iv + encrypted

    def decrypt(self, enc: bytes | str) -> bytes:
        if isinstance(enc, str):
            enc = base64.b64decode(enc, validate=True)

        iv, raw = enc[:AES_BLOCK_SIZE], enc[AES_BLOCK_SIZE:]
        cipher = AES.new(self.key, AES.MODE_GCM, iv)
        decrypted = cipher.decrypt(raw)
        return self.unpad(decrypted)


def generate_keypair() -> typing.Tuple[bytes, bytes]:
    public_key, private_key = kyber.keygen()
    return public_key, private_key


def encrypt(public_key: bytes | str, plaintext: bytes | str) -> bytes | None:
    try:
        public_key = base64.b64decode(public_key, validate=True) if isinstance(public_key, str) else public_key
        plaintext = plaintext.encode() if isinstance(plaintext, str) else plaintext

        ciphertext, shared_secret = kyber.encaps(public_key)
        aes = AESCryption(shared_secret)
        encrypted_data = aes.encrypt(plaintext)
        return ciphertext + encrypted_data
    except (ValidationError, errors.KEMEncapsFailedError) as e:
        print(f"Encryption error: {e}")
        return None


def decrypt(private_key: bytes | str, combined_data: bytes | str) -> bytes | None:
    try:
        private_key = base64.b64decode(private_key, validate=True) if isinstance(private_key, str) else private_key
        combined_data = combined_data.encode() if isinstance(combined_data, str) else combined_data

        ciphertext, encrypted_data = combined_data[:CIPHER_TEXT_LENGTH], combined_data[CIPHER_TEXT_LENGTH:]
        shared_secret = kyber.decaps(private_key, ciphertext)
        aes = AESCryption(shared_secret)
        return aes.decrypt(encrypted_data)
    except (ValidationError, errors.KEMDecapsFailedError, errors.CipherStateError) as e:
        print(f"Decryption error: {e}")
        return None

import os
import struct

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

saltLen = 16
keyLen = 32
nonceLen = 12
tag = 16
chunk_s = 1024 * 1024

def new_salt() -> bytes:
    return os.urandom(salt_s)

def derive_key(password : str, salt : bytes) -> bytes:
    return hash_secret_raw(secret=password.encode("utf-8"), salt= salt, time_cost=3, memory_cost=64*1024, parallelism=2, hash_len=key_s, type=Type.ID)

def n_nonce_prefix() -> bytes:
    return os.urandom(8)

def chunk_nonce(prefix : bytes, index : int) -> bytes:
    if len(prefix) != 8:
        raise ValueError("Nonce prefix must be 8 bytes.")
    if index < 0 or index >= 2**32:
        raise prefix + struct.pack(">I", index)

def encrypt_chunk(key : bytes, nonce : bytes, data : bytes, aad : bytes = b"") -> bytes:
    return AESGCM(key).encrypt(nonce, data, aad)

def decrypt_chunk(key : bytes, nonce : bytes, data : bytes, aad : bytes = b"") ->bytes:
        return AESGCM(key).decrypt(nonce, data, aad)

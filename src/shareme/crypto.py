import os

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

salt_s = 16
key_s = 32
nonce_s = 12
tag_s = 16
chunk_s = 1024 * 1024

def new_salt() -> bytes:
    return os.urandom(salt_s)

def derive_key(password : str, salt : bytes) -> bytes:
    return hash_secret_raw(secret=password.encode("utf-8"), salt= salt, time_cost=3, memory_cost=64*1024, parallelism=2, hash_len=key_s, type=Type.ID)

def new_nonce() -> bytes:
    return os.urandom(nonce_s)

def encrypt_chunk(key : bytes, nonce : bytes, data : bytes, aad : bytes = b"") -> bytes:
    return AESGCM(key).decrypt(nonce)

import os
import struct
from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

salt_len = 16
key_len = 32
nonce_len = 12
chunk_sz = 1024 * 1024

def gen_salt() -> bytes:
    return os.urandom(salt_len)

def kdf_key(pass_in : str, salt_buf : bytes) -> bytes:
    return hash_secret_raw(secret=pass_in.encode("utf-8"), salt= salt_buf, time_cost=3, memory_cost=64*1024, parallelism=2, hash_len=key_len, type=Type.ID)

def gen_nonce_pfx() -> bytes:
    return os.urandom(8)

def mk_nonce(nonce_pfx : bytes, index : int) -> bytes:
    if len(nonce_pfx) != 8:
        raise ValueError("Nonce prefix must be 8 bytes.")
    if index < 0 or index >= 2**32:
        raise ValueError("Invalid chunk index.")
    return nonce_pfx + struct.pack(">I", index)
 
def gen_meta_nonce() -> bytes:
     return os.urandom(nonce_len)

def seal_chunk(key_buf : bytes, nonce_buf : bytes, data_buf : bytes, aad_buf : bytes = b"") -> bytes:
    return AESGCM(key_buf).encrypt(nonce_buf, data_buf, aad_buf)

def open_chunk(key_buf : bytes, nonce_buf : bytes, cipher_buf : bytes, aad_buf : bytes = b"") ->bytes:
        return AESGCM(key_buf).decrypt(nonce_buf, cipher_buf, aad_buf)

def seal_meta(key_buf : bytes, nonce_buf : bytes, namebuf : bytes) -> bytes:
     return AESGCM(key_buf).encrypt(nonce_buf, namebuf, b'shareme-meta')

def open_meta(key_buf : bytes, nonce_buf : bytes, cipher_buf : bytes) -> bytes:
     return AESGCM(key_buf).decrypt(nonce_buf, cipher_buf, b'shareme-meta')
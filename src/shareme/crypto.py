import os
import struct

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

saltLen = 16
keyLen = 32
nonceLen = 12
tagLen = 16
chunkSz = 1024 * 1024

def genSalt() -> bytes:
    return os.urandom(saltLen)

def kdfKey(passIn : str, saltBuf : bytes) -> bytes:
    return hash_secret_raw(secret=passIn.encode("utf-8"), salt= saltBuf, time_cost=3, memory_cost=64*1024, parallelism=2, hash_len=keyLen, type=Type.ID)

def genNoncePfx() -> bytes:
    return os.urandom(8)

def mkNonce(noncePfx : bytes, index : int) -> bytes:
    if len(noncePfx) != 8:
        raise ValueError("Nonce prefix must be 8 bytes.")
    if index < 0 or index >= 2**32:
        raise noncePfx + struct.pack(">I", index)

def sealChunk(keyBuf : bytes, nonceBuf : bytes, cipher : bytes, aad : bytes = b"") -> bytes:
    return AESGCM(key).encrypt(nonce, data, aad)

def decrypt_chunk(key : bytes, nonce : bytes, data : bytes, aad : bytes = b"") ->bytes:
        return AESGCM(key).decrypt(nonce, data, aad)

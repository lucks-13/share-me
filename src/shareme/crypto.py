import os
import struct
from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

saltlen = 16
keylen = 32
noncelen = 12
taglen = 16
chunksz = 1024 * 1024

def gensalt() -> bytes:
    return os.urandom(saltlen)

def kdfkey(passin : str, saltbuf : bytes) -> bytes:
    return hash_secret_raw(secret=passin.encode("utf-8"), salt= saltbuf, time_cost=3, memory_cost=64*1024, parallelism=2, hash_len=keylen, type=Type.ID)

def genNoncePfx() -> bytes:
    return os.urandom(8)

def mkNonce(noncePfx : bytes, index : int) -> bytes:
    if len(noncePfx) != 8:
        raise ValueError("Nonce prefix must be 8 bytes.")
    if index < 0 or index >= 2**32:
        raise ValueError("Invalid chunk index.")
    return noncePfx + struct.pack(">I", index)
    
def genMetaNonce() -> bytes:
     return os.urandom(nonceLen)

def sealChunk(keyBuf : bytes, nonceBuf : bytes, dataBuf : bytes, aadBuf : bytes = b"") -> bytes:
    return AESGCM(keyBuf).encrypt(nonceBuf, dataBuf, aadBuf)

def openChunk(keyBuf : bytes, nonceBuf : bytes, cipherBuf : bytes, aadBuf : bytes = b"") ->bytes:
        return AESGCM(keyBuf).decrypt(nonceBuf, cipherBuf, aadBuf)

def sealMeta(keyBuf : bytes, nonceBuf : bytes, nameBuf : bytes) -> bytes:
     return AESGCM(keyBuf).encrypt(nonceBuf, nameBuf, b'shareme-meta')

def openMeta(keyBuf : bytes, nonceBuf : bytes, cipherBuf : bytes) -> bytes:
     return AESGCM(keyBuf).decrypt(nonceBuf, cipherBuf, b'shareme-meta')
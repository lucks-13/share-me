import os
import struct
from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

salt_len = 16
key_len = 32
noncelen = 12
taglen = 16
chunk_sz = 1024 * 1024

def gen_salt() -> bytes:
    return os.urandom(salt_len)

def kdf_key(pass_in : str, saltbuf : bytes) -> bytes:
    return hash_secret_raw(secret=pass_in.encode("utf-8"), salt= saltbuf, time_cost=3, memory_cost=64*1024, parallelism=2, hash_len=key_len, type=Type.ID)

def gennoncepfx() -> bytes:
    return os.urandom(8)

def mknonce(noncepfx : bytes, index : int) -> bytes:
    if len(noncepfx) != 8:
        raise ValueError("Nonce prefix must be 8 bytes.")
    if index < 0 or index >= 2**32:
        raise ValueError("Invalid chunk index.")
    return noncepfx + struct.pack(">I", index)
 
def gen_meta_nonce() -> bytes:
     return os.urandom(noncelen)

def sealchunk(keybuf : bytes, noncebuf : bytes, databuf : bytes, aadbuf : bytes = b"") -> bytes:
    return AESGCM(keybuf).encrypt(noncebuf, databuf, aadbuf)

def openchunk(keybuf : bytes, noncebuf : bytes, cipherbuf : bytes, aadbuf : bytes = b"") ->bytes:
        return AESGCM(keybuf).decrypt(noncebuf, cipherbuf, aadbuf)

def sealmeta(keybuf : bytes, noncebuf : bytes, namebuf : bytes) -> bytes:
     return AESGCM(keybuf).encrypt(noncebuf, namebuf, b'shareme-meta')

def openmeta(keybuf : bytes, noncebuf : bytes, cipherbuf : bytes) -> bytes:
     return AESGCM(keybuf).decrypt(noncebuf, cipherbuf, b'shareme-meta')
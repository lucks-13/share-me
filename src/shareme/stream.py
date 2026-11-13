from collections.abc import BinaryIO
from .crypto import (chunk_nonce, decrypt_chunk, encrypt_chunk, chunk_s)

def encrypt_stream(source : BinaryIO, target : BinaryIO, key : bytes, nonce_prefix : bytes) -> None:
    index = 0
    while True:
        chunk = source.read(chunk_s)
        if not chunk:
            break
        nonce = chunk_nonce(nonce_prefix, index)
        aad = index.to_bytes(8, "big")
        encrypted = encrypt_chunk(key, nonce, chunk, aad)
        target.write(len(encrypted).to_bytes(4, "big"))
        target.write(encrypted)
        index+=1

def decrypt_stream(source : BinaryIO, target : BinaryIO, key : bytes, nonce_prefix : bytes) -> None:
    while True:
        raw_size = source.read(4)
        if not raw_size:
            break
        if len(raw_size) != 4:
            raise ValueError("Truncated chunk header.")
        size = int.from_bytes(raw_size, "big")
        encrypted = source.read(size)
        if len(encrypted) != size:
            raise ValueError("Truncated chunk header")
        nonce = chunk_nonce(nonce_prefix, index)
        aad 
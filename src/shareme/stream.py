from collections.abc import BinaryIO
from .crypto import (chunk_nonce, decrypt_chunk, encrypt_chunk, chunk_s)

def encrypt_stream(source : BinaryIO, target : BinaryIO, key : bytes, nonce_prefix : bytes) -> None:
    index = 0
    while True:
        chunk = source.read(chunk_s)
        if not chunk:
            break
        nonce = 
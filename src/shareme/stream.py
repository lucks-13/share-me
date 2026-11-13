from collections.abc import BinaryIO
from .crypto import chunkSz, mkNonce, openChunk, sealChunk

def sealStream(source : BinaryIO, target : BinaryIO, keyBuf : bytes, noncePfx : bytes) -> None:
    index = 0
    while chunk:= source.read(chunk_s):
        nonce = chunk_nonce(nonce_prefix, index)
        aad = index.to_bytes(8, "big")
        encrypted = encrypt_chunk(key, nonce, chunk, aad)
        target.write(len(encrypted).to_bytes(4, "big"))
        target.write(encrypted)
        index+=1

def decrypt_stream(source : BinaryIO, target : BinaryIO, key : bytes, nonce_prefix : bytes) -> None:
    index = 0
    while raw_size := source.read(4):
        size = int.from_bytes(raw_size, "big")
        encrypted = source.read(size)
        if len(encrypted) != size:
            raise ValueError("Truncated chunk header")
        nonce = chunk_nonce(nonce_prefix, index)
        aad = index.to_bytes(8, "big")
        decrypted = decrypt_chunk(key, nonce, encrypted, aad)
        target.write(decrypted)
        index += 1
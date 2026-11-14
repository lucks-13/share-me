from typing import BinaryIO
from .crypto import chunk_sz, mk_nonce, open_chunk, seal_chunk

def seal_stream(source : BinaryIO, target : BinaryIO, key_buf : bytes, nonce_pfx : bytes) -> tuple[int, int]:
    index = 0
    byte_cnt = 0
    while True:
        data_buf = source.read(chunk_sz)
        if not data_buf:
            break
        nonce_buf = mk_nonce(nonce_pfx, index)
        aad_buf = index.to_bytes(8, "big")
        cipher_buf = seal_chunk(key_buf, nonce_buf, data_buf, aad_buf)
        target.write(len(cipher_buf).to_bytes(4, "big"))
        target.write(cipher_buf)
        byte_cnt+=len(data_buf)
        index +=1
    return index, byte_cnt

def openstream(source : BinaryIO, target : BinaryIO, key_buf : bytes, nonce_pfx : bytes, file_sz : int) -> tuple[int, int]:
    index = 0
    byte_cnt = 0
    while True:
        size_buf = source.read(4)
        if not size_buf:
            break
        if len(size_buf) != 4:
            raise ValueError("Truncated chunk header.")
        cipher_sz = int.from_bytes(size_buf, "big")
        if cipher_sz < 17:
            raise ValueError("Invalid encrypted chunk size.")
        cipher_buf = source.read(cipher_sz)
        if len(cipher_buf) != cipher_sz:
            raise ValueError("Truncated encrypted chunk.")
        nonce_buf = mk_nonce(nonce_pfx, index)
        aad_buf = index.to_bytes(8, "big")
        data_buf = open_chunk(key_buf, nonce_buf, cipher_buf, aad_buf)
        target.write(data_buf)
        byte_cnt += len(data_buf)
        index+=1
    if byte_cnt != file_sz:
        raise ValueError("File Size Verification failed.")
    return index, byte_cnt
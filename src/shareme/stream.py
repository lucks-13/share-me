from typing import BinaryIO
from .crypto import chunk_sz, mknonce, openchunk, sealchunk

def sealstream(source : BinaryIO, target : BinaryIO, keybuf : bytes, noncepfx : bytes) -> tuple[int, int]:
    index = 0
    byte_cnt = 0
    while True:
        databuf = source.read(chunk_sz)
        if not databuf:
            break
        noncebuf = mknonce(noncepfx, index)
        aadbuf = index.to_bytes(8, "big")
        cipherbuf = sealchunk(keybuf, noncebuf, databuf, aadbuf)
        target.write(len(cipherbuf).to_bytes(4, "big"))
        target.write(cipherbuf)
        byte_cnt+=len(databuf)
        index +=1
    return index, byte_cnt

def openstream(source : BinaryIO, target : BinaryIO, keybuf : bytes, noncepfx : bytes, file_sz : int) -> tuple[int, int]:
    index = 0
    byte_cnt = 0
    while True:
        sizebuf = source.read(4)
        if not sizebuf:
            break
        if len(sizebuf) != 4:
            raise ValueError("Truncated chunk header.")
        ciphersz = int.from_bytes(sizebuf, "big")
        if ciphersz < 17:
            raise ValueError("Invalid encrypted chunk size.")
        cipherbuf = source.read(ciphersz)
        if len(cipherbuf) != ciphersz:
            raise ValueError("Truncated encrypted chunk.")
        noncebuf = mknonce(noncepfx, index)
        aadbuf = index.to_bytes(8, "big")
        databuf = openchunk(keybuf, noncebuf, cipherbuf, aadbuf)
        target.write(databuf)
        byte_cnt += len(databuf)
        index+=1
    if byte_cnt != file_sz:
        raise ValueError("File Size Verification failed.")
    return index, byte_cnt
from typing import BinaryIO
from .crypto import chunksz, mknonce, openchunk, sealchunk

def sealstream(source : BinaryIO, target : BinaryIO, keybuf : bytes, noncepfx : bytes) -> tuple[int, int]:
    index = 0
    bytecnt = 0
    while True:
        databuf = source.read(chunksz)
        if not databuf:
            break
        noncebuf = mknonce(noncepfx, index)
        aadbuf = index.to_bytes(8, "big")
        cipherbuf = sealchunk(keybuf, noncebuf, databuf, aadbuf)
        target.write(len(cipherbuf).to_bytes(4, "big"))
        target.write(cipherbuf)
        bytecnt+=len(databuf)
        index +=1
    return index, bytecnt

def openstream(source : BinaryIO, target : BinaryIO, keybuf : bytes, noncepfx : bytes, filesz : int) -> tuple[int, int]:
    index = 0
    bytecnt = 0
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
        bytecnt += len(databuf)
        index+=1
    if bytecnt != filesz:
        raise ValueError("File Size Verification failed.")
    return index, bytecnt
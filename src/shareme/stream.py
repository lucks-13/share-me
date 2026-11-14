from typing import BinaryIO
from collections.abc import Iterable, Iterator
from .crypto import chunksz, mknonce, openchunk, sealchunk

def sealStream(source : BinaryIO, target : BinaryIO, keybuf : bytes, noncepfx : bytes) -> tuple[int, int]:
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

def openStream(source : BinaryIO, target : BinaryIO, keybuf : bytes, noncepfx : bytes, filesz : int) -> tuple[int, int]:
    index = 0
    bytecnt = 0
    while True:
        sizeBuf = source.read(4)
        if not sizeBuf:
            break
        if len(sizeBuf) != 4:
            raise ValueError("Truncated chunk header.")
        cipherSz = int.from_bytes(sizeBuf, "big")
        if cipherSz < 17:
            raise ValueError("Invalid encrypted chunk size.")
        cipherBuf = source.read(cipherSz)
        if len(cipherBuf) != cipherSz:
            raise ValueError("Truncated encrypted chunk.")
        nonceBuf = mkNonce(noncePfx, index)
        aadBuf = index.to_bytes(8, "big")
        dataBuf = openChunk(keyBuf, nonceBuf, cipherBuf, aadBuf)
        target.write(dataBuf)
        byteCnt += len(dataBuf)
        index+=1
    if byteCnt != fileSz:
        raise ValueError("File Size Verification failed.")
    return index, byteCnt
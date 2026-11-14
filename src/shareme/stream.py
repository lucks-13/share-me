from typing import BinaryIO
from .crypto import chunkSz, mkNonce, openChunk, sealChunk

def sealStream(source : BinaryIO, target : BinaryIO, keyBuf : bytes, noncePfx : bytes) -> tuple[int, int]:
    index = 0
    byteCnt = 0
    while True:
        dataBuf = source.read(chunkSz)
        if not dataBuf:
            break
        nonceBuf = mkNonce(noncePfx, index)
        aadBuf = index.to_bytes(8, "big")
        cipherBuf = sealChunk(keyBuf, nonceBuf, dataBuf, aadBuf)
        target.write(len(cipherBuf).to_bytes(4, "big"))
        target.write(cipherBuf)
        byteCnt+=len(dataBuf)
        index +=1
    return index, byteCnt

def openStream(source : BinaryIO, target : BinaryIO, keyBuf : bytes, noncePfx : bytes, fileSz : int) -> tuple[int, int]:
    index = 0
    byteCnt = 0
    while True:
        sizeBuf = source.read(4)
        if not sizeBuf:
            break
        if len(sizeBuf) != 4:
            raise ValueError("Truncated chunk header.")
        if cipherSz < 17:
            raise ValueError("Invalid encrypted chunk size.")
        cipherSz = int.from_bytes(sizeBuf, "big")
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
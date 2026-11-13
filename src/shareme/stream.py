from collections.abc import BinaryIO
from .crypto import chunkSz, mkNonce, openChunk, sealChunk

def sealStream(source : BinaryIO, target : BinaryIO, keyBuf : bytes, noncePfx : bytes) -> None:
    index = 0
    while True:
        dataBuf = source.read(chunkSz)
        if not dataBuf:
            break
        nonceBuf = mkNonce(noncePfx, index)
        aadBuf = index.to_bytes(8, "big")
        cipherBuf = sealChunk(keyBuf, nonceBuf, dataBuf, aadBuf)
        target.write(len(cipherBuf).to_bytes(4, "big"))
        target.write(cipherBuf)
        index +=1
    return index


def openStream(source : BinaryIO, target : BinaryIO, keyBuf : bytes, noncePfx : bytes) -> int:
    index = 0
    while True:
        sizeBuf = source.read(4)
        if not sizeBuf:
            break
        if len(sizeBuf) != 4:
            raise ValueError("T")
    
import struct
from dataclasses import dataclass
from .crypto import saltLen

magic = b"share-me"
v = 1
hdr_fmt = ">8sBB16s8sQ"
hdr_sz = struct.calcsize(hdr_fmt)

@dataclass
class Hdr:
    saltBuf : bytes
    nonceBuf : bytes
    fileSz : int

def packHdr(hdr : Hdr) -> bytes:
    if len(hdr.saltBuf) != saltLen:
        raise ValueError("Invalid salt size.")
    if len(hdr.noncePfx) != 8:
        raise ValueError("Invalid nonce prefix size.")
    if hdr.fileSz < 0:
        raise ValueError("invalid file size.")
    return struct.pack(hdr_fmt, magic, v, 0, hdr.saltBuf, hdr.noncePfx, hdr.fileSz)
    
def readHdr(dataBuf : bytes) -> Hdr:
    if len(dataBuf) != hdr_sz:
        raise ValueError("Invalid ShareMe header size.")
    magicBuf, ver, flags, saltBuf, noncePfx, fileSz = struct.unpack(hdr_fmt, dataBuf)
    if magicBuf != magic:
        raise ValueError("Invalid ShareMe magic.")
    if ver != v:
        raise ValueError("Unsupported ShareMe Version.")
    if flags != 0:
        raise ValueError("Unsupported ShareMe flags.")
    return Hdr(saltBuf=saltBuf, noncePfx=noncePfx, fileSz=fileSz)
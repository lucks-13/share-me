import struct
from dataclasses import dataclass
from .crypto import saltlen, noncelen

magic = b"share-me"
v = 1
hdr_fmt = ">8sBB16s8sQQ12s"
hdr_sz = struct.calcsize(hdr_fmt)

@dataclass(frozen=True)
class Hdr:
    saltBuf : bytes
    noncePfx : bytes
    fileSz : int
    metaNonce : bytes
    metaSz : int

def packHdr(hdr : Hdr) -> bytes:
    if len(hdr.saltBuf) != saltLen:
        raise ValueError("Invalid salt size.")
    if len(hdr.noncePfx) != 8:
        raise ValueError("Invalid nonce prefix size.")
    if len(hdr.metaNonce) != nonceLen:
        raise ValueError("Invalid metadata nonce size.")
    if hdr.fileSz < 0:
        raise ValueError("Invalid file size.")
    if hdr.metaSz < 1:
        raise ValueError("Invalid metadata size.")
    return struct.pack(hdr_fmt, magic, v, 0, hdr.saltBuf, hdr.noncePfx, hdr.fileSz, hdr.metaSz, hdr.metaNonce)

def readHdr(dataBuf : bytes) -> Hdr:
    if len(dataBuf) != hdr_sz:
        raise ValueError("Invalid ShareMe header size.")
    magicBuf, ver, flags, saltBuf, noncePfx, fileSz, metaSz, metaNonce = struct.unpack(hdr_fmt, dataBuf)
    if magicBuf != magic:
        raise ValueError("Invalid ShareMe magic.")
    if ver != v:
        raise ValueError("Unsupported ShareMe Version.")
    if len(saltBuf) != saltLen:
        raise ValueError("Invalid salt size.")
    if len(metaNonce) != nonceLen:
        raise ValueError("Invalid metadata nonce size.")
    if len(noncePfx) != 8:
        raise ValueError("Invalid nonce prefix size.")
    if flags != 0:
        raise ValueError("Unsupported ShareMe flags.")
    if metaSz < 1:
        raise ValueError("Invalid metadata size.")
    return Hdr(saltBuf=saltBuf, noncePfx=noncePfx, fileSz=fileSz, metaNonce=metaNonce, metaSz=metaSz)

import struct
from dataclasses import dataclass
from .crypto import saltlen, noncelen

magic = b"share-me"
v = 1
hdr_fmt = ">8sBB16s8sQQ12s"
hdr_sz = struct.calcsize(hdr_fmt)

@dataclass(frozen=True)
class Hdr:
    saltbuf : bytes
    noncepfx : bytes
    file_sz : int
    metanonce : bytes
    metasz : int

def packhdr(hdr : Hdr) -> bytes:
    if len(hdr.saltbuf) != saltlen:
        raise ValueError("Invalid salt size.")
    if len(hdr.noncepfx) != 8:
        raise ValueError("Invalid nonce prefix size.")
    if len(hdr.metanonce) != noncelen:
        raise ValueError("Invalid metadata nonce size.")
    if hdr.file_sz < 0:
        raise ValueError("Invalid file size.")
    if hdr.metasz < 1:
        raise ValueError("Invalid metadata size.")
    return struct.pack(hdr_fmt, magic, v, 0, hdr.saltbuf, hdr.noncepfx, hdr.file_sz, hdr.metasz, hdr.metanonce)

def readhdr(databuf : bytes) -> Hdr:
    if len(databuf) != hdr_sz:
        raise ValueError("Invalid ShareMe header size.")
    magicbuf, ver, flags, saltbuf, noncepfx, file_sz, metasz, metanonce = struct.unpack(hdr_fmt, databuf)
    if magicbuf != magic:
        raise ValueError("Invalid ShareMe magic.")
    if ver != v:
        raise ValueError("Unsupported ShareMe Version.")
    if len(saltbuf) != saltlen:
        raise ValueError("Invalid salt size.")
    if len(metanonce) != noncelen:
        raise ValueError("Invalid metadata nonce size.")
    if len(noncepfx) != 8:
        raise ValueError("Invalid nonce prefix size.")
    if flags != 0:
        raise ValueError("Unsupported ShareMe flags.")
    if metasz < 1:
        raise ValueError("Invalid metadata size.")
    return Hdr(saltbuf=saltbuf, noncepfx=noncepfx, file_sz=file_sz, metanonce=metanonce, metasz=metasz)

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
    return struct.pack(hdr_fmt, magic, v, 0, hdr.saltBuf, hdr.nonceP)

    
def unpack_header(data : bytes) -> Header:
    Magic, V, _, salt, nonce_p, file_s = struct.unpack(header_f, data)
    if magic != magic or v != V:
        raise ValueError("Unsupported ShareMe format.")
    return Header(salt=salt, nonce_p = nonce_p, file_s=file_s)

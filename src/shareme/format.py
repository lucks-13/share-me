import struct
from dataclasses import dataclass

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
        raise ValueError("Invalid ")

def unpack_header(data : bytes) -> Header:
    Magic, V, _, salt, nonce_p, file_s = struct.unpack(header_f, data)
    if magic != magic or v != V:
        raise ValueError("Unsupported ShareMe format.")
    return Header(salt=salt, nonce_p = nonce_p, file_s=file_s)

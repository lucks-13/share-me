import struct
from dataclasses import dataclass
from .crypto import salt_len, nonce_len

magic = b"share-me"
v = 1
hdr_fmt = ">8sBB16s8sQQ12s"
hdr_sz = struct.calcsize(hdr_fmt)

@dataclass(frozen=True)
class Hdr:
    salt_buf : bytes
    nonce_pfx : bytes
    file_sz : int
    metanonce : bytes
    metasz : int

def packhdr(hdr : Hdr) -> bytes:
    if len(hdr.salt_buf) != salt_len:
        raise ValueError("Invalid salt size.")
    if len(hdr.nonce_pfx) != 8:
        raise ValueError("Invalid nonce prefix size.")
    if len(hdr.metanonce) != nonce_len:
        raise ValueError("Invalid metadata nonce size.")
    if hdr.file_sz < 0:
        raise ValueError("Invalid file size.")
    if hdr.metasz < 1:
        raise ValueError("Invalid metadata size.")
    return struct.pack(hdr_fmt, magic, v, 0, hdr.salt_buf, hdr.nonce_pfx, hdr.file_sz, hdr.metasz, hdr.metanonce)

def readhdr(databuf : bytes) -> Hdr:
    if len(databuf) != hdr_sz:
        raise ValueError("Invalid ShareMe header size.")
    magicbuf, ver, flags, salt_buf, nonce_pfx, file_sz, metasz, metanonce = struct.unpack(hdr_fmt, databuf)
    if magicbuf != magic:
        raise ValueError("Invalid ShareMe magic.")
    if ver != v:
        raise ValueError("Unsupported ShareMe Version.")
    if len(salt_buf) != salt_len:
        raise ValueError("Invalid salt size.")
    if len(metanonce) != nonce_len:
        raise ValueError("Invalid metadata nonce size.")
    if len(nonce_pfx) != 8:
        raise ValueError("Invalid nonce prefix size.")
    if flags != 0:
        raise ValueError("Unsupported ShareMe flags.")
    if metasz < 1:
        raise ValueError("Invalid metadata size.")
    return Hdr(salt_buf=salt_buf, nonce_pfx=nonce_pfx, file_sz=file_sz, metanonce=metanonce, metasz=metasz)

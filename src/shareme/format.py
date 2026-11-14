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
    meta_nonce : bytes
    meta_sz : int

def pack_hdr(hdr : Hdr) -> bytes:
    if len(hdr.salt_buf) != salt_len:
        raise ValueError("Invalid salt size.")
    if len(hdr.nonce_pfx) != 8:
        raise ValueError("Invalid nonce prefix size.")
    if len(hdr.meta_nonce) != nonce_len:
        raise ValueError("Invalid metadata nonce size.")
    if hdr.file_sz < 0:
        raise ValueError("Invalid file size.")
    if hdr.meta_sz < 1:
        raise ValueError("Invalid metadata size.")
    return struct.pack(hdr_fmt, magic, v, 0, hdr.salt_buf, hdr.nonce_pfx, hdr.file_sz, hdr.meta_sz, hdr.meta_nonce)

def read_hdr(data_buf : bytes) -> Hdr:
    if len(data_buf) != hdr_sz:
        raise ValueError("Invalid ShareMe header size.")
    magic_buf, ver, flags, salt_buf, nonce_pfx, file_sz, meta_sz, meta_nonce = struct.unpack(hdr_fmt, data_buf)
    if magic_buf != magic:
        raise ValueError("Invalid ShareMe magic.")
    if ver != v:
        raise ValueError("Unsupported ShareMe Version.")
    if len(salt_buf) != salt_len:
        raise ValueError("Invalid salt size.")
    if len(meta_nonce) != nonce_len:
        raise ValueError("Invalid metadata nonce size.")
    if len(nonce_pfx) != 8:
        raise ValueError("Invalid nonce prefix size.")
    if flags != 0:
        raise ValueError("Unsupported ShareMe flags.")
    if meta_sz < 1:
        raise ValueError("Invalid metadata size.")
    return Hdr(salt_buf=salt_buf, nonce_pfx=nonce_pfx, file_sz=file_sz, meta_nonce=meta_nonce, meta_sz=meta_sz)

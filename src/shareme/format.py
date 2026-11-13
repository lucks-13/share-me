import struct
from dataclasses import dataclass

magic = b"share-me"
v = 1
header_f = ">8sBB16s8sQ"
header_s = struct.calcsize(header_f)

@dataclass
class Header:
    salt : bytes
    nonce_p : bytes
    file_s : int

def pack_header(header : Header) -> bytes:
    return magic, v,0,header.salt, header.nonce_p, header.file_s

def unpack_header(data : bytes) -> Header:
    Magic, , _, salt, nonce_p, file_s = struct.unpack(header_f, data)
    if magic !
import base64
import binascii
from typing import BinaryIO, TextIO
from .errors import invalidsharemeerror

def encode(data : bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")

def decode(text : str) -> bytes:
    try:
        return base64.urlsafe_b64decode(text.encode("ascii"))
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise invalidsharemeerror("Invalid ShareMe encoding.") from exc

def encode_stream(source : BinaryIO, target : TextIO, chuncksize : int = 1024*1024) -> None:
    pending = b""
    while True:
        data_buf = source.read(chuncksize)
        if not data_buf:
            break
        data_buf = pending + data_buf
        use_sz = len(data_buf) - (len(data_buf)%3)
        if use_sz:
            target.write(base64.urlsafe_b64encode(data_buf[:use_sz]).decode("ascii"))
            pending = data_buf[use_sz:]
    if pending:
        target.write(base64.urlsafe_b64encode(pending).decode("ascii"))

def decode_stream(source : TextIO, target : BinaryIO, chunksize : int = 1024*1024) -> None:
    pending = ""
    while True:
        text_buf = source.read(chunksize)
        if not text_buf:
            break
        pending += text_buf
        use_sz = len(pending) - (len(pending) % 4)
        if use_sz:
            try:
                target.write(base64.urlsafe_b64decode(pending[:use_sz].encode("ascii")))
            except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
                raise invalidsharemeerror("Invalid ShareMe encoding.") from exc
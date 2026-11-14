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

def encodestream(source : BinaryIO, target : TextIO, chuncksize : int = 1024*1024) -> None:
    pending = b""
    while True:
        databuf = source.read(chuncksize)
        if not databuf:
            break
        databuf = pending + databuf
        usesz = len(databuf) - (len(databuf)%3)
        if usesz:
            target.write(base64.urlsafe_b64encode(databuf[:usesz]).decode("ascii"))
            pending = databuf[usesz:]
    if pending:
        target.write(base64.urlsafe_b64encode(pending).decode("ascii"))

def decodestream(source : TextIO, target : BinaryIO, chunksize : int = 1024*1024) -> None:
    pending = ""
    while True:
        textbuf = source.read(chunksize)
        if not textbuf:
            break
        pending += textbuf
        usesz = len(pending) - (len(pending) % 4)
        if usesz:
            try:
                target.write(base64.urlsafe_b64decode(pending[:usesz].encode("ascii")))
            except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
                raise invalidsharemeerror("Invalid ShareMe encoding.") from exc
import base64
import binascii
from typing import BinaryIO, TextIO
from .errors import InvalidShareMeError

def encode(data : bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")

def decode(text : str) -> bytes:
    try:
        return base64.urlsafe_b64decode(text.encode("ascii"))
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise InvalidShareMeError("Invalid ShareMe encoding.") from exc

def encodeStream(source : BinaryIO, target : TextIO, chunckSize : int = 1024*1024) -> None:
    pending = b""
    while True:
        dataBuf = source.read(chunckSize)
        if not dataBuf:
            break
        dataBuf = pending + dataBuf
        useSz = len(dataBuf) - (len(dataBuf)%3)
        if useSz:
            target.write(base64.urlsafe_b64encode(dataBuf[:useSz]).decode("ascii"))
            pending = dataBuf[useSz:]
    if pending:
        target.write(base64.urlsafe_b64encode(pending).decode("ascii"))

def decodeStream(source : TextIO, target : BinaryIO, chunkSize : int = 1024*1024) -> None:
    pending = ""
    while True:
        textBuf = source.read(chunkSize)
        if not textBuf:
            break
        pending += textBuf
        useSz = len(pending) - (len(pending) % 4)
        if useSz:
            try:
                target.write(base64.urlsafe_b64decode(pending[:useSz].encode("ascii")))
            except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
                raise InvalidShareMeError("Invalid ShareMe encoding.") from exc 
    
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

def encodeStream(source : BinaryIO, tar)
    
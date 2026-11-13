import base64
import binascii

from .errors import InvalidShareMeError

def encode(data : bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")

def decode(text : bytes) -> bytes:
    try:
        return base64.urlsafe_b64decode(text.encode("ascii"))
    except:
        
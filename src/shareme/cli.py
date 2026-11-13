import os
import tempfile
import typer
import base64
import binascii
from pathlib import Path
from .crypto import genMetaNonce, genNoncePfx, genSalt, kdfKey, openMeta, sealMeta
from .encoding import encode, decode
from .errors import ShareMeError
from .format import hdr_sz, Hdr, packHdr, readHdr
from .stream import openStream, sealStream

app = typer.Typer(
    name = "shareme",
    help = "Secure text based file sharing cli."
)

def getPass(prompt : str) -> str:
    return typer.prompt(prompt, hide_input=True)

def readFileName(metaBuf : bytes) -> str:
    try:
        nameStr = metaBuf.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ShareMeError("Invalid encrypted filename.") from exc
    return nameStr

def makeOpname(nameStr : str) -> str:
    c_name = Path(nameStr).name
    if c_name in {"",".",".."}:
        raise ShareMeError("Invalid output filename.")
    return c_name

@app.command()
def encrypt(inputPath : Path = typer.Argument(...))

@app.command()
def decrypt() -> None:
    typer.echo("Decrypt command testing")

if __name__ == "__main__":
    app()
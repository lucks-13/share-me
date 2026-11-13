import os
import tempfile
import typer
import base64
import binascii
from pathlib import Path
from .crypto import genMetaNonce, genNoncePfx, genSalt, kdfKey, openMeta, sealMeta
from .encoding import encode, decode
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
    except UnicodeDecodeError as exc

@app.command()
def encrypt(file : str, output : str = typer.Option(None, "-o")) -> None:
    password = typer.prompt("Password", hide_input=True)
    confirm = typer.prompt("Confirm password", hide_input=True)
    if password != confirm:
        typer.echo("Error : Passwords do not match.", err=True)
        raise typer.Exit(1)
    size = os.path.getsize(file)
    salt = new_salt()
    nonce_p = n_nonce_prefix()
    key = derive_key(password, salt)
    header = pack_header(Header(salt=salt, nonce_p=nonce_p, file_s=size))
    with open(file, "rb") as source, tempfile.TemporaryFile("w+b") as temp:
        temp.write(header)
        encrypt_stream(source, temp, key, nonce_p)
        temp.seek(0)
        text = encode(temp.read())
    output = output or f"{file}.shareme"
    with open(output, "w", encoding="ascii", newline="") as target:
        target.write("ShareMe : ")
        target.write(text)
    typer.echo(f"Output : {output}")

@app.command()
def decrypt() -> None:
    typer.echo("Decrypt command testing")

if __name__ == "__main__":
    app()
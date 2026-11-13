import os
import tempfile
import typer
import base64
import binascii
from cryptography.exceptions import InvalidTag
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
def encrypt(inPath : Path = typer.Argument(..., exists=True, readable=True), outPath : Path = typer.Option(Path("shareme.txt"), "--output", "-o")) -> None:
    if not inPath.is_file():
        raise typer.BadParameter("Input path must be a file.")
    passIn = getPass("Password")
    passChk = getPass("Confirm Password")
    if passIn != passChk:
        raise typer.BadParameter("Passwords do not match.")
    fileSz = inPath.stat().st_size
    saltBuf = genSalt()
    keyBuf = kdfKey(passIn, saltBuf)
    noncePfx = genNoncePfx()
    metaNonce = genMetaNonce()
    nameBuf = inPath.name.encode("utf-8")
    metaBuf = sealMeta(keyBuf, metaNonce, nameBuf)
    hdr = Hdr(saltBuf=saltBuf, noncePfx=noncePfx, fileSz=fileSz, metaNonce=metaNonce, metaSz=len(metaBuf))
    if outPath.exists():
        raise typer.BadParameter(f"Output file already exists : {outPath}")
    with tempfile.TemporaryFile() as rawOut:
        rawOut.write(packHdr(hdr))
        rawOut.write(metaBuf)
        with inPath.open("rb") as source:
            sealStream(source, rawOut, keyBuf, noncePfx)
        rawOut.seek(0)
        rawBuf = rawOut.read()
    textOut = encode(rawBuf)
    with outPath.open("w", encoding="ascii", newline="\n") as target:
        target.write("ShareMe : ")
        target.write(textOut)
        target.write("\n")
    typer.echo(f"Encrypted : {inPath} -> {outPath}")

@app.command()
def decrypt(inPath : Path = typer.Argument(..., exists=True, readable=True), outPath : Path | None = typer.Option(None, "--output", "-o")) -> None:
    with inPath.open("r", encoding="ascii") as source:
        textBuf = source.read().strip()
        if not textBuf.startswith("ShareMe : "):
            raise typer.BadParameter("Invalid ShareMe file.")
        payload = textBuf[len("ShareMe : "):]
        try:
            rawBuf = decode(payload)
        except ShareMeError as exc:
            raise typer.BadParameter(str(exc)) from exc
        if len(rawBuf) < hdr_sz:
            raise typer.BadParameter("ShareMe file is too short.")
        hdr = readHdr(rawBuf[:hdr_sz])
        metaEnd = hdr_sz + hdr.metaSz
        if len(rawBuf) < metaEnd:
            raise typer.BadParameter("Truncated metadata.")
        metaBuf = rawBuf[hdr_sz:metaEnd]
        chunkBuf = rawBuf[metaEnd:]
        passIn = getPass("Password")
        keyBuf = kdfKey(passIn, hdr.saltBuf)
        try:
            nameBuf = openMeta(keyBuf, hdr.metaNonce, metaBuf)
            nameStr = readFileName(nameBuf)
            if outPath is None:
                outPath = Path(makeOpname(nameStr))
            if outPath.exists():
                raise typer.BadParameter(f"Output file already exists : {outPath}")
            outPath.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(mode="wb", dir=outPath.parent, prefix=f"{outPath.name}.", suffix=".tmp", delete=False) as tempFile:
                tempPath = Path(tempFile.name)
                try:
                    tempSrc = tempfile.TemporaryFile()
                    try:
                        tempSrc.write(chunkBuf)
                        tempSrc.seek(0)
                        openStream(tempSrc, tempFile, keyBuf, hdr.noncePfx, hdr.fileSz)
                    finally:
                        tempSrc.close()
                except Exception:
                    tempPath.unlink(missing_ok=True)
                    raise
        except InvalidTag as exc:
            raise typer.BadParameter("Incorrect password or corrupted ShareMe data") from exc
        except (ValueError, ShareMeError) as exc:
            tempPath = locals().get("tempPath")
            if tempPath is not None:
                tempPath.unlink(missing_ok=True)
            raise typer.BadParameter(str(exc)) from exc
    tempPath.replace(outPath)
    typer.echo(f"Decrypted : {inPath} -> {outPath}")
    
if __name__ == "__main__":
    app()
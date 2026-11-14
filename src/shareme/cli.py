import tempfile
import typer
from cryptography.exceptions import InvalidTag
from pathlib import Path
from .crypto import genmetanonce, gennoncepfx, gensalt, kdfkey, openmeta, sealmeta
from .encoding import encodestream, decodestream
from .errors import sharemeerror
from .format import hdr_sz, Hdr, packhdr, readhdr
from .stream import openstream, sealstream

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
    if not nameStr:
        raise ShareMeError("Empty encrypted filename.") from exc
    return nameStr

def makeOpname(nameStr : str) -> str:
    c_name = Path(nameStr).name
    if c_name in {"",".",".."}:
        raise ShareMeError("Invalid output filename.")
    return c_name

@app.command()
def encrypt(inpath : Path = typer.Argument(..., exists=True, readable=True), outpath : Path = typer.Option(Path("shareme.txt"), "--output", "-o")) -> None:
    if not inpath.is_file():
        raise typer.BadParameter("Input path must be a file.")
    passin = getpass("Password ")
    passchk = getpass("Confirm Password ")
    if passin != passchk:
        raise typer.BadParameter("Passwords do not match.")
    if outpath.exists():
        raise typer.BadParameter(f"Output file already exists : {outpath}")
    filesz = inpath.stat().st_size
    saltbuf = gensalt()
    keybuf = kdfkey(passin, saltbuf)
    noncepfx = gennoncepfx()
    metanonce = genmetanonce()
    namebuf = inpath.name.encode("utf-8")
    metabuf = sealmeta(keybuf, metanonce, namebuf)
    hdr = Hdr(saltbuf=saltbuf, noncepfx=noncepfx, filesz=filesz, metaNonce=metanonce, metasz=len(metabuf))
    with tempfile.TemporaryFile() as rawout:
        rawout.write(packhdr(hdr))
        rawout.write(metabuf)
        with inpath.open("rb") as source:
            sealstream(source, rawout, keybuf, noncepfx)
        rawout.seek(0)
        with outpath.open("w", encoding="ascii", newline="\n") as target:
            target.write("ShareMe : ")
            encodestream(rawout, target)
            target.write("\n")
    typer.echo(f"Encrypted : {inpath} -> {outpath}")

@app.command()
def decrypt(inpath : Path = typer.Argument(..., exists=True, readable=True), outpath : Path | None = typer.Option(None, "--output", "-o")) -> None:
    with inpath.open("r", encoding="ascii") as source:
        prefix = source.read(len("ShareMe : "))
        if prefix != "ShareMe : ":
            typer.BadParameter("Invalid ShareMe file.")
        with tempfile.TemporaryFile() as rawin:
            try:
                decodestream(source, rawin):
            except sharemeerror as exc:
                raise typer.BadParameter(str(exc)) from exc
            rawin.seek(0)
        if len(rawbuf) < hdr_sz:
            raise typer.BadParameter("ShareMe file is too short.")
        hdr = readHdr(rawbuf[:hdr_sz])
        metaEnd = hdr_sz + hdr.metaSz
        if len(rawBuf) < metaEnd:
            raise typer.BadParameter("Truncated metadata.")
        metaBuf = rawBuf[hdr_sz:metaEnd]
        chunkBuf = rawBuf[metaEnd:]
        passIn = getPass("Password ")
        keyBuf = kdfKey(passIn, hdr.saltBuf)
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
                with tempfile.TemporaryFile() as tempSrc:
                    tempSrc.write(chunkBuf)
                    tempSrc.seek(0)
                    openStream(tempSrc, tempFile, keyBuf, hdr.noncePfx, hdr.fileSz)
                    tempPath.replace(outPath)
            except InvalidTag as exc:
                if tempPath is not None:
                    tempPath.unlink(missing_ok=True)
                raise typer.BadParameter("Incorrect password or corrupted ShareMe data") from exc
            except (ValueError, ShareMeError) as exc:
                if tempPath is not None:
                    tempPath.unlink(missing_ok=True)
                    raise typer.BadParameter(str(exc)) from exc
            typer.echo(f"Decrypted : {inPath} -> {outPath}")

if __name__ == "__main__":
    app()
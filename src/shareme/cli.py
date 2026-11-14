import tempfile
import typer
from cryptography.exceptions import InvalidTag
from pathlib import Path
from .crypto import gen_meta_nonce, gennoncepfx, gen_salt, kdf_key, openmeta, sealmeta
from .encoding import encodestream, decodestream
from .errors import sharemeerror
from .format import hdr_sz, Hdr, packhdr, readhdr
from .stream import openstream, sealstream

app = typer.Typer(
    name = "shareme",
    help = "Secure text based file sharing cli."
)

def get_pass(prompt : str) -> str:
    return typer.prompt(prompt, hide_input=True)

def readfilename(metabuf : bytes) -> str:
    try:
        namestr = metabuf.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise sharemeerror("Invalid encrypted filename.") from exc
    if not namestr:
        raise sharemeerror("Empty encrypted filename.") from exc
    return namestr

def makeopname(namestr : str) -> str:
    c_name = Path(namestr).name
    if c_name in {"",".",".."}:
        raise sharemeerror("Invalid output filename.")
    return c_name

@app.command()
def encrypt(inpath : Path = typer.Argument(..., exists=True, readable=True), outpath : Path = typer.Option(Path("shareme.txt"), "--output", "-o")) -> None:
    if not inpath.is_file():
        raise typer.BadParameter("Input path must be a file.")
    pass_in = get_pass("Password ")
    passchk = get_pass("Confirm Password ")
    if pass_in != passchk:
        raise typer.BadParameter("Passwords do not match.")
    if outpath.exists():
        raise typer.BadParameter(f"Output file already exists : {outpath}")
    file_sz = inpath.stat().st_size
    saltbuf = gen_salt()
    keybuf = kdf_key(pass_in, saltbuf)
    noncepfx = gennoncepfx()
    metanonce = gen_meta_nonce()
    namebuf = inpath.name.encode("utf-8")
    metabuf = sealmeta(keybuf, metanonce, namebuf)
    hdr = Hdr(saltbuf=saltbuf, noncepfx=noncepfx, file_sz=file_sz, metanonce=metanonce, metasz=len(metabuf))
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
                decodestream(source, rawin)
            except sharemeerror as exc:
                raise typer.BadParameter(str(exc)) from exc
            rawin.seek(0)
            headerbuf = rawin.read(hdr_sz)
            if len(headerbuf) < hdr_sz:
                raise typer.BadParameter("ShareMe file is too short.")
            try:
                hdr = readhdr(headerbuf)
            except ValueError as exc:
                raise typer.BadParameter(str(exc)) from exc
            metabuf = rawin.read(hdr.metasz)
            if len(metabuf) < hdr.metasz:
                raise typer.BadParameter("Truncated metadata.")
            pass_in = get_pass("Password ")
            try:
                keybuf = kdf_key(pass_in, hdr.saltbuf)
                namebuf = openmeta(keybuf, hdr.metanonce, metabuf)        
            except InvalidTag as exc:
                raise typer.BadParameter("Incorrect password or corrupted ShareMe data.") from exc
            namestr = readfilename(namebuf)
            if outpath is None:
                outpath = Path(makeopname(namestr))
            if outpath.exists():
                raise typer.BadParameter(f"Output file already exists : {outpath}")
            outpath.parent.mkdir(parents=True, exist_ok=True)
            temppath = None
            try:
                with tempfile.NamedTemporaryFile(mode="wb", dir=outpath.parent, prefix=f"{outpath.name}.", suffix=".tmp", delete=False) as tempfiles:
                    temppath = Path(tempfiles.name)
                    openstream(rawin, tempfiles, keybuf, hdr.noncepfx, hdr.file_sz)
                temppath.replace(outpath)
            except InvalidTag as exc:
                if temppath is not None:
                    temppath.unlink(missing_ok=True)
                    raise typer.BadParameter("Incorrect password or corrupted ShareMe data.") from exc
            except (ValueError, sharemeerror) as exc:
                if temppath is not None:
                    temppath.unlink(missing_ok=True)
                    raise typer.BadParameter(str(exc)) from exc
            typer.echo(f"Decrypted : {inpath} -> {outpath}")     

if __name__ == "__main__":
    app()
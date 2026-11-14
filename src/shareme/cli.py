import tempfile
import typer
from cryptography.exceptions import InvalidTag
from pathlib import Path
from .crypto import gen_meta_nonce, gen_nonce_pfx, gen_salt, kdf_key, open_meta, seal_meta
from .encoding import encode_stream, decode_stream
from .errors import sharemeerror
from .format import hdr_sz, Hdr, pack_hdr, read_hdr
from .stream import open_stream, seal_stream

app = typer.Typer(
    name = "share-me",
    help = "Secure text based file sharing cli."
)

def get_pass(prompt : str) -> str:
    return typer.prompt(prompt, hide_input=True)

def read_file_name(meta_buf : bytes) -> str:
    try:
        name_str = meta_buf.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise sharemeerror("Invalid encrypted filename.") from exc
    if not name_str:
        raise sharemeerror("Empty encrypted filename.") from exc
    return name_str

def mk_encrypt_path(out_path : Path) -> Path:
    if out_path.name in {"", ".", ".."}:
        raise sharemeerror("Invalid output filename.")
    if out_path.suffix == ".shareme":
        return out_path
    return out_path.with_name(out_path.name + ".shareme")

def mk_restore_path(out_path : Path, name_str : str) -> Path:
    base_name = Path(out_path).name
    if base_name in {"", ".", ".."}:
        raise sharemeerror("Invalid output filename.")
    ext = Path(name_str).suffix
    if not ext:
        return out_path
    return out_path.with_name(base_name + ext)

@app.command()
def encrypt(in_path : Path = typer.Argument(..., exists=True, readable=True), out_path : Path = typer.Option(Path("shareme.txt"), "--output", "-o")) -> None:
    if not in_path.is_file():
        raise typer.BadParameter("Input path must be a file.")
    pass_in = get_pass("Password ")
    passchk = get_pass("Confirm Password ")
    if pass_in != passchk:
        raise typer.BadParameter("Passwords do not match.")
    
    if out_path.exists():
        raise typer.BadParameter(f"Output file already exists : {out_path}")
    file_sz = in_path.stat().st_size
    salt_buf = gen_salt()
    key_buf = kdf_key(pass_in, salt_buf)
    nonce_pfx = gen_nonce_pfx()
    meta_nonce = gen_meta_nonce()
    name_buf = in_path.name.encode("utf-8")
    meta_buf = seal_meta(key_buf, meta_nonce, name_buf)
    hdr = Hdr(salt_buf=salt_buf, nonce_pfx=nonce_pfx, file_sz=file_sz, meta_nonce=meta_nonce, meta_sz=len(meta_buf))
    with tempfile.TemporaryFile() as raw_out:
        raw_out.write(pack_hdr(hdr))
        raw_out.write(meta_buf)
        with in_path.open("rb") as source:
            seal_stream(source, raw_out, key_buf, nonce_pfx)
        raw_out.seek(0)
        with out_path.open("w", encoding="ascii", newline="\n") as target:
            target.write("ShareMe : ")
            encode_stream(raw_out, target)
            target.write("\n")
    typer.echo(f"Encrypted : {in_path} -> {out_path}")

@app.command()
def decrypt(in_path : Path = typer.Argument(..., exists=True, readable=True), out_path : Path | None = typer.Option(None, "--output", "-o")) -> None:
    with in_path.open("r", encoding="ascii") as source:
        prefix = source.read(len("ShareMe : "))
        if prefix != "ShareMe : ":
            typer.BadParameter("Invalid ShareMe file.")
        with tempfile.TemporaryFile() as raw_in:
            try:
                decode_stream(source, raw_in)
            except sharemeerror as exc:
                raise typer.BadParameter(str(exc)) from exc
            raw_in.seek(0)
            header_buf = raw_in.read(hdr_sz)
            if len(header_buf) < hdr_sz:
                raise typer.BadParameter("ShareMe file is too short.")
            try:
                hdr = read_hdr(header_buf)
            except ValueError as exc:
                raise typer.BadParameter(str(exc)) from exc
            meta_buf = raw_in.read(hdr.meta_sz)
            if len(meta_buf) < hdr.meta_sz:
                raise typer.BadParameter("Truncated metadata.")
            pass_in = get_pass("Password ")
            try:
                key_buf = kdf_key(pass_in, hdr.salt_buf)
                name_buf = open_meta(key_buf, hdr.meta_nonce, meta_buf)        
            except InvalidTag as exc:
                raise typer.BadParameter("Incorrect password or corrupted ShareMe data.") from exc
            name_str = read_file_name(name_buf)
            if out_path is None:
                out_path = Path(makeopname(name_str))
            if out_path.exists():
                raise typer.BadParameter(f"Output file already exists : {out_path}")
            out_path.parent.mkdir(parents=True, exist_ok=True)
            temp_path = None
            try:
                with tempfile.NamedTemporaryFile(mode="wb", dir=out_path.parent, prefix=f"{out_path.name}.", suffix=".tmp", delete=False) as temp_file:
                    temp_path = Path(temp_file.name)
                    open_stream(raw_in, temp_file, key_buf, hdr.nonce_pfx, hdr.file_sz)
                temp_path.replace(out_path)
            except InvalidTag as exc:
                if temp_path is not None:
                    temp_path.unlink(missing_ok=True)
                    raise typer.BadParameter("Incorrect password or corrupted ShareMe data.") from exc
            except (ValueError, sharemeerror) as exc:
                if temp_path is not None:
                    temp_path.unlink(missing_ok=True)
                    raise typer.BadParameter(str(exc)) from exc
            typer.echo(f"Decrypted : {in_path} -> {out_path}")     

if __name__ == "__main__":
    app()
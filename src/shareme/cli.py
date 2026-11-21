import tempfile
import typer
import json
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

def make_op_name(name_str : str) -> str:
    c_name = Path(name_str).name
    if c_name in {"",".",".."}:
        raise sharemeerror("Invalid output filename.")
    return c_name

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

def split_csv_path(raw : list[str] | None) -> list[Path]:
    if not raw:
        return []
    res : list[Path] = []
    for i in raw:
        for p in i.split(","):
            c = p.strip()
            if c:
                res.append(Path(c))
    return res

def parse_meta_bundle(meta_buf : bytes) -> list[tuple[str, int]] | None:
    try:
        text = meta_buf.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text.startswith("["):
        return None
    try:
        entries = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(entries, list) or not entries:
        return None
    parsed : list[tuple[str, int]] = []
    for i in entries:
        if not isinstance(i, dict) or "name" not in i or "size" not in i:
            return None
        name_str = i["name"]
        size_val = i["size"]
        if not isinstance(name_str, str) or not name_str or not isinstance(size_val, int) or size_val < 0:
            return None
        parsed.append((make_op_name(name_str), size_val))
    return parsed

def write_atomic(dest : Path, reader) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    temp_path : Path | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", dir=dest.parent, prefix=f"{dest.name}.") as temp_file:
            temp_path = Path(temp_file.name)
            reader(temp_file)
        temp_path.replace(dest)
    except InvalidTag as exc:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
        raise typer.BadParameter("Incorrect password or corrupted ShareMe data.") from exc
    except (ValueError,sharemeerror) as exc:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
        raise typer.BadParameter(str(exc)) from exc


@app.command()
def encrypt(in_path : list[str] = typer.Argument(..., exists=True, readable=True), out_path : Path = typer.Option(Path("shareme.txt"), "--output", "-o")) -> None:
    files = split_csv_path(in_path)
    if not files:
        raise typer.BadParameter("At least one input file is required.")
    for f in files:
        if not f.exists() or not f.is_file():
            raise typer.BadParameter(f"Input path must be a file : {f}")
    pass_in = get_pass("Password ")
    pass_chk = get_pass("Confirm Password ")
    if pass_in != pass_chk:
        raise typer.BadParameter("Passwords do not match.")
    out_path = mk_encrypt_path(out_path)
    if out_path.exists():
        raise typer.BadParameter(f"Output file already exists : {out_path}")
    salt_buf = gen_salt()
    key_buf = kdf_key(pass_in, salt_buf)
    nonce_pfx = gen_nonce_pfx()
    meta_nonce = gen_meta_nonce()
    if len(files) == 1:
        s = files[0]
        file_sz = s.stat().st_size
        name_buf = s.name.encode("utf-8")
    else:
        manifest = [{"name" : i.name, "size" : i.stat().st_size} for i in files]
        file_sz = sum(item["size"] for item in manifest)
        name_buf = json.dumps(manifest, separators=(",",":")).encode("utf-8")
    meta_buf = seal_meta(key_buf, meta_nonce, name_buf)
    hdr = Hdr(salt_buf=salt_buf, nonce_pfx=nonce_pfx, file_sz=file_sz, meta_nonce=meta_nonce, meta_sz=len(meta_buf))
    with tempfile.TemporaryFile() as source:
        for f in files:
            with f.open("rb") as src_part:
                while True:
                    buf = src_part.read(1024 * 1024)
                    if not buf:
                        break
                    source.write(buf)
        source.seek(0)    
    with tempfile.TemporaryFile() as raw_out:
        raw_out.write(pack_hdr(hdr))
        raw_out.write(meta_buf)
        seal_stream(source, raw_out, key_buf, nonce_pfx)
        raw_out.seek(0)
        with out_path.open("w", encoding="ascii", newline="\n") as target:
            target.write("ShareMe : ")
            encode_stream(raw_out, target)
            target.write("\n")
    typer.echo(f"Encrypted : {', '.join(str(p) for p in files)} -> {out_path}")

@app.command()
def decrypt(in_path : list[str] = typer.Argument(..., exists=True, readable=True), out_path : list[str] | None = typer.Option(None, "--output", "-o")) -> None:
    archives = split_csv_path(in_path)
    if not archives:
        raise typer.BadParameter("At least one input file is required.")
    for arch in archives:
        if not arch.exists() or not arch.is_file():
            raise typer.BadParameter(f"Input path must be a file : {arch}")
    target = split_csv_path(out_path)
    if target and len(target) != len(archives):
        raise typer.BadParameter("Output count must match input file count.")
    pass_in = get_pass("Password ")
    for idx, arch in enumerate(archives):
        out_target = target[idx] if target else None
        with arch.open("r", encoding="ascii") as source:
            prefix = source.read(len("ShareMe : "))
            if prefix != "ShareMe : ":
                raise typer.BadParameter("Invalid ShareMe file.")
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
                key_buf = kdf_key(pass_in, hdr.salt_buf)
                try:
                    plain_meta = open_meta(key_buf, hdr.meta_nonce, meta_buf)
                except InvalidTag as exc:
                    raise typer.BadParameter("Incorrect password or corrupted ShareMe data.") from exc
                bundle_entries = parse_meta_bundle(plain_meta)
                if bundle_entries is None:
                    name_str = read_file_name(plain_meta)
                    dest = Path(make_op_name(name_str)) if out_target is None else mk_restore_path(out_target, name_str)
                    if dest.exists():
                        raise typer.BadParameter(f"Output file already exists : {dest}")
                    write_atomic(dest, lambda tf : open_stream(raw_in, tf, key_buf, hdr.nonce_pfx, hdr.file_sz))
                    typer.echo(f"Decrypted : {arch} -> {dest}")
                else:
                    dest_dir = Path(".") if out_target is None else out_target
                    resolved : list[tuple[str, int, Path]] = []
                    for entry_name, entry_sz in bundle_entries:
                        dest = dest_dir / entry_name
                        if dest.exists():
                            raise typer.BadParameter(f"Output file already exists : {dest}")
                        resolved.append((entry_name, entry_sz, dest))
                    with tempfile.TemporaryFile() as c_out:
                        try:
                            open_stream(raw_in, c_out, key_buf, hdr.nonce_pfx, hdr.file_sz)
                        except (ValueError, sharemeerror) as exc:
                            raise typer.BadParameter(str(exc)) from exc
                        c_out.seek(0)
                        written : list[Path] = []
                        for _, entry_sz, dest in resolved:
                            def copy_slice(tf, sz = entry_sz) -> None:
                                remain = sz
                                while remain > 0:
                                    chunk = c_out.read(min(remain, 1024 * 1024))
                                    if not chunk:
                                        raise ValueError("File Size Verification failed.")
                                    tf.write(chunk)
                                    remain -= len(chunk)
                            write_atomic(dest, copy_slice)
                            written.append(dest)
                    typer.echo(f"Decrypted : {arch} -> {', '.join(str(p) for p in written)}")
                    
if __name__ == "__main__":
    app()
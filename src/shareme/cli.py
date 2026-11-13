import os
import tempfile
import typer
from .crypto import derive_key, new_salt, n_nonce_prefix
from .encoding import encode
from .format import Header, pack_header
from .stream import encrypt_stream

app = typer.Typer(
    name = "shareme",
    help = "Secure text based file sharing cli."
)

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
        text = en
    typer.echo("Encryption key derived successfully.")
    typer.echo(f"Key size : {len(key)*8} bits.")

@app.command()
def decrypt() -> None:
    typer.echo("Decrypt command testing")

if __name__ == "__main__":
    app()
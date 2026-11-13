import typer
from .crypto import derive_key, new_salt

app = typer.Typer(
    name = "shareme",
    help = "Secure text based file sharing cli."
)

@app.command()
def encrypt() -> None:
    password = typer.prompt("Password", hide_input=True)
    confirm = typer.prompt("Confirm password", hide_input=True)
    if password != confirm:
        typer.echo("Error : Passwords do not match.", err=True)
        raise typer.Exit(1)
    salt = new_salt()
    key = derive_key(password, salt)
    typer.echo("Encryption key derived successfully.")
    typer.

@app.command()
def decrypt() -> None:
    typer.echo("Decrypt command testing")

if __name__ == "__main__":
    app()
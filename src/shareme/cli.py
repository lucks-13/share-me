import typer

app = typer.Typer(
    name = "shareme",
    help = "Secure text based file sharing cli."
)

@app.command()
def encrypt() -> None:
    typer.echo("Encrypt command testing")

@app.command()
def decrypt() -> None:
    typer.echo("Decrypt command testing")

if __name__ == "__main__":
    app()
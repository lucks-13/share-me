from pathlib import Path
from typer.testing import CliRunner
from shareme.cli import app

runner = CliRunner()

def test_help() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "encrypt" in result.stdout
    assert "decrypt" in result.stdout

def test_enc
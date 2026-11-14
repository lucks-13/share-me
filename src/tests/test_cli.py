from pathlib import Path
from typer.testing import CliRunner
from shareme.cli import app

runner = CliRunner()

def test_help() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "encrypt" in result.stdout
    assert "decrypt" in result.stdout

def test_encrypt_and_decrypt(tmp_path : Path) -> None:
    source = tmp_path / "test.txt"
    encrypt = tmp_path / "test.shareme"
    restore = tmp_path / "restored.txt"
    source.write_text("Test Message", encoding="utf-8")
    
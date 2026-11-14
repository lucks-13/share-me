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
    result = runner.invoke(app, ["encrypt", str(source), "-o", str(encrypt)], input="password\npassword\n")
    assert result.exit_code == 0
    assert encrypt.exists()
    result = runner.invoke(app, ["decrypt", str(encrypt), "-o", str(restore)], input="password\n")
    assert result.exit_code == 0
    assert restore.read_text(encoding="utf-8") == "Test Message"

def test_binary_file(tmp_path : Path) -> None:
    source = tmp_path / "test.bin"
    encrypt = tmp_path / "test.shareme"
    restore = tmp_path / "restored.bin"
    data = bytes(range(256))*100
    source.write_bytes(data)
    result = runner.invoke(app, ["encrypt", str(source), "-o", str(encrypt)], input="password\npassword\n")
    assert result.exit_code == 0
    assert encrypt.exists()
    result = runner.invoke(app, ["decrypt", str(encrypt), "-o", str(restore)], input="password\n")
    assert result.exit_code == 0
    assert restore.read_bytes() == data

def test_empty_file(tmp_path : Path) -> None:
    source = tmp_path / "test.txt"
    encrypt = tmp_path / "test.shareme"
    restore = tmp_path / "restored.txt"
    source.write_bytes(b"")
    result = runner.invoke(app, ["encrypt", str(source), "-o", str(encrypt)], input="password\npassword\n")
    assert result.exit_code == 0
    assert encrypt.exists()
    result = runner.invoke(app, ["decrypt", str(encrypt), "-o", str(restore)], input="password\n")
    assert result.exit_code == 0
    assert restore.read_bytes() == b""

def test_wrong_password(tmp_path : Path) -> None:
    source = tmp_path / "test.txt"
    encrypt = tmp_path / "test.shareme"
    restore = tmp_path / "restored.txt"
    source.write_text("Test Message", encoding="utf-8")
    result = runner.invoke(app, ["encrypt", str(source), "-o", str(encrypt)], input="correct\ncorrect\n")
    assert result.exit_code == 0
    assert encrypt.exists()
    result = runner.invoke(app, ["decrypt", str(encrypt), "-o", str(restore)], input="wrong\n")
    assert result.exit_code != 0
    assert not restore.exists()

def test_corrupt_file(tmp_path : Path) -> None:
    source = tmp_path / "test.txt"
    encrypt = tmp_path / "test.shareme"
    corrupt = tmp_path / "corrupt.shareme"
    restore = tmp_path / "restored.txt"
    source.write_text("Test Message", encoding="utf-8")
    result = runner.invoke(app, ["encrypt", str(source), "-o", str(encrypt)], input="correct\ncorrect\n")
    assert result.exit_code == 0
    data = encrypt.read_text(encoding="ascii")
    corrupt.write_text(data[:20]+("A" if data[20] != "A" else "B")+data[21:], encoding="ascii")
    result = runner.invoke(app, ["decrypt", str(corrupt), "-o", str(restore)], input="correct\n")
    assert result.exit_code != 0
    assert not restore.exists()

def test_encryption(tmp_path : Path) -> None:
    source = tmp_path / "test.txt"
    encrypt_1 = tmp_path / "test_1.shareme"
    encrypt_2 = tmp_path / "test_2.shareme"
    source.write_text("Test Message", encoding="utf-8")
    result = runner.invoke(app, ["encrypt", str(source), "-o", str(encrypt_1)], input="password\npassword\n")
    assert result.exit_code == 0
    result = runner.invoke(app, ["encrypt", str(source), "-o", str(encrypt_2)], input="password\npassword\n")
    assert result.exit_code == 0
    assert encrypt_1.read_bytes() != encrypt_2.read_bytes()

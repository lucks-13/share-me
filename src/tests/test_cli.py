from pathlib import Path
from typer.testing import CliRunner
from shareme.cli import app

runner = CliRunner()

def test_help() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "encrypt" in result.stdout
    assert "decrypt" in result.stdout
    assert "share-me" in result.stdout

def test_encrypt_and_decrypt(tmp_path : Path) -> None:
    source = tmp_path / "test.txt"
    encrypt = tmp_path / "test.shareme"
    restore = tmp_path / "restored"
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
    restore = tmp_path / "restored"
    data = bytes(range(256))*100
    source.write_bytes(data)
    result = runner.invoke(app, ["encrypt", str(source), "-o", str(encrypt)], input="password\npassword\n")
    assert result.exit_code == 0
    assert encrypt.exists()
    result = runner.invoke(app, ["decrypt", str(encrypt), "-o", str(restore)], input="password\n")
    assert result.exit_code == 0
    assert restore.read_bytes() == data

def test_video_file(tmp_path : Path) -> None:
    source = tmp_path / "test.mp4"
    encrypt = tmp_path / "test.shareme"
    restore = tmp_path / "restored"
    data = b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42isom\x00\x00\x00\x08mdat"
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
    restore = tmp_path / "restored"
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
    restore = tmp_path / "restored"
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
    restore = tmp_path / "restored"
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

def test_large_file(tmp_path : Path) -> None:
    source = tmp_path / "test.bin"
    encrypt = tmp_path / "test.shareme"
    restore = tmp_path / "restored"
    data = bytes(range(256))*409600 # 100 Mb
    # data = bytes(range(256))*20971520 # 5 Gb
    # data = bytes(range(256))*41943040 # 10 Gb
    source.write_bytes(data)
    result = runner.invoke(app, ["encrypt", str(source), "-o", str(encrypt)], input="password\npassword\n")
    assert result.exit_code == 0
    assert encrypt.exists()
    result = runner.invoke(app, ["decrypt", str(encrypt), "-o", str(restore)], input="password\n")
    assert result.exit_code == 0
    assert restore.read_bytes() == data

def test_encrypt_and_decrypt_multiple_file(tmp_path : Path) -> None:
    f1 = tmp_path / "file1" / "test1.txt"
    f2 = tmp_path / "file2" / "test2.txt"
    f1.parent.mkdir(parents=True, exist_ok=True)
    f2.parent.mkdir(parents=True, exist_ok=True)
    out_base = tmp_path / "test"
    restore_dir = tmp_path / "restore"
    f1.write_text("Hello 1", encoding="utf-8")
    f2.write_text("Hello 2", encoding="utf-8")
    res1 = runner.invoke(app, ["encrypt", f"{f1}, {f2}", "-o", str(out_base)], input="password\npassword\n")
    assert res1.exit_code == 0
    assert (tmp_path / "test.shareme").exists()
    res2 = runner.invoke(app, ["decrypt", str(tmp_path / "test.shareme"), "-o", str(restore_dir)], input="password\n")
    assert res2.exit_code == 0
    assert (restore_dir / "test1.txt").read_text(encoding = "utf-8") == "Hello 1"
    assert (restore_dir / "test2.txt").read_text(encoding = "utf-8") == "Hello 2"

def test_decrypt_multiple_archives(tmp_path : Path) -> None:
    s1 = tmp_path / "a.txt"
    s2 = tmp_path / "b.txt"
    s1.write_text("Hello 1", encoding="utf-8")
    s2.write_text("Hello 2", encoding="utf-8")
    a1 = runner.invoke(app, ["encrypt", str(s1), "-o", str(tmp_path / "test1.shareme")], input="pasword\npassword\n")
    a2 = runner.invoke(app, ["encrypt", str(s2), "-o", str(tmp_path / "test2.shareme")], input="pasword\npassword\n")
    assert a1.exit_code == 0
    assert a2.exit_code == 0
    r1 = tmp_path / "restore1"
    r2 = tmp_path / "restore2"
    res = runner.invoke(app, ["decrypt", f"{tmp_path / 'test1.shareme'}, {tmp_path / 'test2.shareme'}", "-o", f"{r1}, {r2}"], input="password\n")
    assert res.exit_code == 0
    assert r1.read_text(encoding="utf-8") == "Hello 1"
    assert r2.read_text(encoding="utf-8") == "Hello 2"
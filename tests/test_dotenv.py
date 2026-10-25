from farpoint.cli import load_dotenv


def test_load_dotenv(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("# comment\nA_KEY=abc   # note\nexport B_KEY='q'\nEMPTY=   # blank\nKEEP=file\n")
    for k in ("A_KEY", "B_KEY", "EMPTY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("KEEP", "shell")
    load_dotenv(env)
    import os
    assert os.environ["A_KEY"] == "abc"
    assert os.environ["B_KEY"] == "q"
    assert "EMPTY" not in os.environ
    assert os.environ["KEEP"] == "shell"

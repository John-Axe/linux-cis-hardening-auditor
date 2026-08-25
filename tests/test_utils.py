from cis_audit import utils


def test_run_cmd_missing_binary_returns_minus_one():
    rc, out, err = utils.run_cmd(["definitely-not-a-real-binary-xyz"])
    assert rc == -1
    assert out == ""
    assert "not found" in err


def test_run_cmd_success():
    rc, out, err = utils.run_cmd(["echo", "hello"])
    assert rc == 0
    assert out == "hello"


def test_path_mode_octal_missing_path():
    assert utils.path_mode_octal("/no/such/path/xyz") is None


def test_path_mode_octal_real_file(tmp_path):
    f = tmp_path / "thing"
    f.write_text("x")
    f.chmod(0o640)
    assert utils.path_mode_octal(str(f)) == "640"


def test_path_owner_missing_path():
    assert utils.path_owner("/no/such/path/xyz") is None


def test_read_text_missing_file():
    assert utils.read_text("/no/such/path/xyz") is None


def test_read_text_real_file(tmp_path):
    f = tmp_path / "thing"
    f.write_text("line1\nline2\n")
    assert utils.read_text(str(f)) == "line1\nline2\n"


def test_read_lines(tmp_path):
    f = tmp_path / "thing"
    f.write_text("a\nb\nc")
    assert utils.read_lines(str(f)) == ["a", "b", "c"]


def test_read_lines_missing_file():
    assert utils.read_lines("/no/such/path/xyz") is None


def test_sysctl_value_prefers_proc_sys(monkeypatch):
    monkeypatch.setattr(utils, "read_text", lambda path: "1\n" if path == "/proc/sys/kernel/foo" else None)
    assert utils.sysctl_value("kernel.foo") == "1"


def test_sysctl_value_falls_back_to_binary(monkeypatch):
    monkeypatch.setattr(utils, "read_text", lambda path: None)
    monkeypatch.setattr(utils, "run_cmd", lambda args, timeout=5.0: (0, "2", ""))
    assert utils.sysctl_value("kernel.foo") == "2"


def test_sysctl_value_none_when_unreadable(monkeypatch):
    monkeypatch.setattr(utils, "read_text", lambda path: None)
    monkeypatch.setattr(utils, "run_cmd", lambda args, timeout=5.0: (-1, "", "not found"))
    assert utils.sysctl_value("kernel.foo") is None


def test_redact_never_echoes_value():
    secret = "$6$abcdefgh$reallylonghashvalue"
    redacted = utils.redact(secret)
    assert secret not in redacted
    assert "redacted" in redacted


def test_redact_empty():
    assert utils.redact("") == "(empty)"

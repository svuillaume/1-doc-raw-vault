import os, subprocess, sys
from pathlib import Path
import pytest
import raw_vault as v


@pytest.fixture(autouse=True)
def master(monkeypatch):
    monkeypatch.setenv("VAULT_MASTER", v.b64(os.urandom(32)))


def tree(root, files):
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text)


def test_roundtrip_and_nothing_readable_in_the_vault(tmp_path):
    raw, vault, out = tmp_path / "raw", tmp_path / "vault", tmp_path / "out"
    tree(raw, {"a.txt": "secret alpha", "files/b.txt": "secret beta"})
    v.encrypt(raw, vault, "2026-10")
    blob = b"".join(p.read_bytes() for p in vault.rglob("*") if p.is_file())
    assert b"secret" not in blob and b"a.txt" not in blob
    v.decrypt(vault, out, "2026-10")
    assert (out / "a.txt").read_text() == "secret alpha" and (out / "files/b.txt").read_text() == "secret beta"


def test_unchanged_files_keep_their_ciphertext_and_removed_files_go(tmp_path):
    raw, vault = tmp_path / "raw", tmp_path / "vault"
    tree(raw, {"a.txt": "one", "b.txt": "two"})
    v.encrypt(raw, vault, "2026-10")
    before = {p.name: p.read_bytes() for p in (vault / "data").iterdir()}
    (raw / "b.txt").unlink()
    tree(raw, {"c.txt": "three"})
    v.encrypt(raw, vault, "2026-10")
    after = {p.name: p.read_bytes() for p in (vault / "data").iterdir()}
    kept = [n for n in before if n in after]
    assert len(kept) == 1 and before[kept[0]] == after[kept[0]] and len(after) == 2


def test_monthly_wrap_changes_only_the_wrap_and_old_wraps_are_deleted(tmp_path):
    raw, vault, out = tmp_path / "raw", tmp_path / "vault", tmp_path / "out"
    tree(raw, {"a.txt": "one"})
    v.encrypt(raw, vault, "2026-10")
    data_before = {p.name: p.read_bytes() for p in (vault / "data").iterdir()}
    v.wrap(vault, "2026-11")
    assert {p.name: p.read_bytes() for p in (vault / "data").iterdir()} == data_before
    assert sorted(p.name for p in (vault / "wraps").iterdir()) == ["wrap-2026-10.json", "wrap-2026-11.json"]
    v.wrap(vault, "2026-12")
    assert sorted(p.name for p in (vault / "wraps").iterdir()) == ["wrap-2026-11.json", "wrap-2026-12.json"]
    v.decrypt(vault, out, "2026-12")
    assert (out / "a.txt").read_text() == "one"


def test_wrong_master_and_a_missed_month_are_refused(tmp_path, monkeypatch):
    raw, vault = tmp_path / "raw", tmp_path / "vault"
    tree(raw, {"a.txt": "one"})
    v.encrypt(raw, vault, "2026-10")
    with pytest.raises(SystemExit):   # wraps older than last month are not accepted
        v.decrypt(vault, tmp_path / "o", "2026-12")
    monkeypatch.setenv("VAULT_MASTER", v.b64(os.urandom(32)))
    with pytest.raises(Exception):
        v.decrypt(vault, tmp_path / "o2", "2026-10")


def test_january_wraps_back_to_december():
    assert v.previous("2027-01") == "2026-12" and v.previous("2026-10") == "2026-09"


def test_a_typed_phrase_as_master_is_refused_with_a_clear_message(tmp_path, monkeypatch):
    monkeypatch.setenv("VAULT_MASTER", "thisis%&mypassphrase1^")
    tree(tmp_path / "raw", {"a.txt": "x"})
    with pytest.raises(SystemExit) as e:
        v.encrypt(tmp_path / "raw", tmp_path / "vault", "2026-10")
    assert "genmaster" in str(e.value)


def test_an_openssl_hex_secret_works_as_master(tmp_path, monkeypatch):
    monkeypatch.setenv("VAULT_MASTER", os.urandom(32).hex())
    tree(tmp_path / "raw", {"a.txt": "hello"})
    v.encrypt(tmp_path / "raw", tmp_path / "vault", "2026-10")
    v.decrypt(tmp_path / "vault", tmp_path / "out", "2026-10")
    assert (tmp_path / "out" / "a.txt").read_text() == "hello"

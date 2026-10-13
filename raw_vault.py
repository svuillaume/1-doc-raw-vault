#!/usr/bin/env python3
"""Encrypted copy of 1-doc's raw/ folder, safe to keep in a PRIVATE git repo. Nothing readable ever leaves your machine.

  raw_vault.py genmaster   (or: openssl rand -hex 32)            print a new master secret (keep it out of git)
  VAULT_MASTER=... raw_vault.py encrypt RAW_DIR VAULT_DIR        encrypt new or changed files (unchanged files keep their bytes)
  VAULT_MASTER=... raw_vault.py wrap VAULT_DIR [--month YYYY-MM] re-wrap the data key for this month (run monthly)
  VAULT_MASTER=... raw_vault.py decrypt VAULT_DIR OUT_DIR        restore the files

Two keys: a data key encrypts the files once; each month's key (derived from the master and the month) only wraps the
data key. Rotation therefore changes one tiny file, never the 4 MB of ciphertext. Wraps older than last month are deleted.
"""
import base64, hashlib, json, os, secrets, sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

b64 = lambda b: base64.urlsafe_b64encode(b).decode()
unb64 = lambda s: base64.urlsafe_b64decode(s.encode())


def this_month():
    return datetime.now(timezone.utc).strftime("%Y-%m")


def previous(month):
    y, m = map(int, month.split("-"))
    return f"{y - 1}-12" if m == 1 else f"{y}-{m - 1:02d}"


def master():
    raw = os.environ.get("VAULT_MASTER", "")
    if not raw:
        sys.exit("Set VAULT_MASTER (see genmaster). It is never stored in the vault.")
    try:
        key = unb64(raw)
    except ValueError:
        key = b""
    if len(key) < 32:
        sys.exit("VAULT_MASTER must be a generated key, not a typed phrase: run genmaster (or openssl rand -hex 32) and use what it prints.")
    return key


def month_key(month):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"1-doc-vault", info=b"wrap:" + month.encode()).derive(master())


def seal(key, plain, aad=b""):
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(key).encrypt(nonce, plain, aad)


def unseal(key, blob, aad=b""):
    return AESGCM(key).decrypt(blob[:12], blob[12:], aad)


def write_wrap(vault, dek, month):
    (vault / "wraps").mkdir(parents=True, exist_ok=True)
    (vault / "wraps" / f"wrap-{month}.json").write_text(json.dumps({"month": month, "wrapped": b64(seal(month_key(month), dek, month.encode()))}))


def load_dek(vault, today=None):
    """The data key, from this month's wrap or last month's (a short grace period); anything older is refused."""
    today = today or this_month()
    for month in (today, previous(today)):
        f = vault / "wraps" / f"wrap-{month}.json"
        if f.exists():
            try:
                return unseal(month_key(month), unb64(json.loads(f.read_text())["wrapped"]), month.encode())
            except InvalidTag:
                raise SystemExit("This VAULT_MASTER is not the key this vault was made with. Use the original key, or, if it is lost, delete the vault folder and encrypt again with a new key (and set the same key as the Actions secret).")
    raise SystemExit("No usable wrap for this month or last month. Run wrap with the key that made the vault.")


def wrap(vault, month=None):
    month = month or this_month()
    dek = load_dek(vault, month)
    write_wrap(vault, dek, month)
    for f in (vault / "wraps").glob("wrap-*.json"):
        if f.stem[5:] not in (month, previous(month)):
            f.unlink()


def encrypt(src, vault, month=None):
    month = month or this_month()
    (vault / "data").mkdir(parents=True, exist_ok=True)
    first = not (vault / "wraps").exists() or not any((vault / "wraps").glob("wrap-*.json"))
    dek = secrets.token_bytes(32) if first else load_dek(vault, month)
    if first:
        write_wrap(vault, dek, month)
    mf = vault / "manifest.enc"
    manifest = json.loads(unseal(dek, mf.read_bytes(), b"manifest")) if mf.exists() else {}
    seen = set()
    for f in sorted(p for p in src.rglob("*") if p.is_file()):
        rel = f.relative_to(src).as_posix()
        seen.add(rel)
        data = f.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        name = hashlib.sha256(rel.encode()).hexdigest()[:24] + ".enc"
        if manifest.get(rel, {}).get("sha256") == digest and (vault / "data" / name).exists():
            continue   # unchanged: keep the same ciphertext, so git sees no change
        (vault / "data" / name).write_bytes(seal(dek, data, rel.encode()))
        manifest[rel] = {"file": name, "sha256": digest}
    for rel in set(manifest) - seen:   # removed from raw/: removed from the vault
        (vault / "data" / manifest.pop(rel)["file"]).unlink(missing_ok=True)
    mf.write_bytes(seal(dek, json.dumps(manifest, sort_keys=True).encode(), b"manifest"))


def decrypt(vault, out, month=None):
    dek = load_dek(vault, month or this_month())
    manifest = json.loads(unseal(dek, (vault / "manifest.enc").read_bytes(), b"manifest"))
    for rel, meta in manifest.items():
        target = out / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(unseal(dek, (vault / "data" / meta["file"]).read_bytes(), rel.encode()))


def main(argv):
    if not argv or argv[0] not in ("genmaster", "encrypt", "wrap", "decrypt"):
        sys.exit(__doc__)
    month = argv[argv.index("--month") + 1] if "--month" in argv else None
    args = [a for i, a in enumerate(argv[1:], 1) if a != "--month" and argv[i - 1] != "--month"]
    if argv[0] == "genmaster":
        print(b64(secrets.token_bytes(32)))
    elif argv[0] == "encrypt":
        encrypt(Path(args[0]), Path(args[1]), month)
    elif argv[0] == "wrap":
        wrap(Path(args[0]), month)
    else:
        decrypt(Path(args[0]), Path(args[1]), month)


if __name__ == "__main__":
    main(sys.argv[1:])

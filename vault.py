#!/usr/bin/env python3
"""
Cryptographic Encryption Vault
==============================

Encrypts and decrypts whole directory trees with AES-256-GCM.

Key management design (envelope encryption):
  * A random 256-bit Data Encryption Key (DEK) encrypts all files.
  * The DEK is stored in a key file, wrapped (encrypted) with a Key Encryption
    Key (KEK) derived from your master passphrase using scrypt.
  * Changing the passphrase only re-wraps the DEK; no file re-encryption needed.
  * Timestamped, permission-restricted backups of the key file can be created.

Safety properties:
  * Non-destructive: original files are never modified or deleted.
  * Streaming/chunked AES-GCM: large files never need to fit in memory.
  * Tamper, truncation and chunk-reordering detection (GCM tags + AAD).
  * SHA-256 manifest (itself encrypted) verifies a lossless restore.
  * Atomic writes: output files appear only after being fully written.

Usage: see README.md  (python vault.py --help)
"""

import argparse
import base64
import getpass
import hashlib
import io
import json
import logging
import os
import shutil
import struct
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
MAGIC = b"VLT1"                       # file-format identifier + version
CHUNK_SIZE = 1024 * 1024              # 1 MiB plaintext chunks
HEADER_LEN = 4 + 4 + 8                # magic + chunk size + nonce prefix
TAG_LEN = 16                          # AES-GCM authentication tag
ENC_SUFFIX = ".vlt"
MANIFEST_NAME = "MANIFEST" + ENC_SUFFIX
KEYFILE_AAD = b"vault-keyfile-v1"
MIN_PASSPHRASE_LEN = 12

# scrypt cost parameters (N=2**15 ~ 32 MiB RAM; raise N for more security)
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1

log = logging.getLogger("vault")


class VaultError(Exception):
    """Any expected, user-facing failure."""


# --------------------------------------------------------------------------- #
# Key management
# --------------------------------------------------------------------------- #
def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def _derive_kek(passphrase: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(passphrase.encode("utf-8"))


def _check_passphrase_strength(passphrase: str) -> None:
    if len(passphrase) < MIN_PASSPHRASE_LEN:
        raise VaultError(f"Passphrase must be at least {MIN_PASSPHRASE_LEN} characters.")


def _wrap_dek(dek: bytes, passphrase: str) -> dict:
    salt, nonce = os.urandom(16), os.urandom(12)
    kek = _derive_kek(passphrase, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
    wrapped = AESGCM(kek).encrypt(nonce, dek, KEYFILE_AAD)
    return {
        "version": 1,
        "kdf": "scrypt",
        "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P,
        "salt": _b64e(salt),
        "nonce": _b64e(nonce),
        "wrapped_key": _b64e(wrapped),
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def _write_private(path: Path, data: bytes, exclusive: bool) -> None:
    """Write a file readable only by the owner (0600)."""
    flags = os.O_WRONLY | os.O_CREAT | (os.O_EXCL if exclusive else os.O_TRUNC)
    fd = os.open(str(path), flags, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # e.g. Windows


def create_keyfile(keyfile: Path, passphrase: str) -> None:
    """Generate a fresh random DEK and store it wrapped by the passphrase."""
    _check_passphrase_strength(passphrase)
    if keyfile.exists():
        raise VaultError(f"{keyfile} already exists; refusing to overwrite a key file.")
    dek = os.urandom(32)
    _write_private(keyfile, json.dumps(_wrap_dek(dek, passphrase), indent=2).encode(), exclusive=True)


def load_dek(keyfile: Path, passphrase: str) -> bytes:
    """Unwrap the DEK using the passphrase."""
    try:
        meta = json.loads(keyfile.read_text())
        kek = _derive_kek(passphrase, _b64d(meta["salt"]), meta["n"], meta["r"], meta["p"])
        return AESGCM(kek).decrypt(_b64d(meta["nonce"]), _b64d(meta["wrapped_key"]), KEYFILE_AAD)
    except FileNotFoundError:
        raise VaultError(f"Key file not found: {keyfile}")
    except InvalidTag:
        raise VaultError("Wrong passphrase, or the key file is corrupted.")
    except (KeyError, ValueError, json.JSONDecodeError):
        raise VaultError(f"{keyfile} is not a valid vault key file.")


def backup_keyfile(keyfile: Path, backup_dir: Path) -> Path:
    """Copy the (still passphrase-wrapped) key file to a timestamped backup."""
    if not keyfile.is_file():
        raise VaultError(f"Key file not found: {keyfile}")
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = backup_dir / f"{keyfile.stem}-{stamp}.key.bak"
    data = keyfile.read_bytes()
    _write_private(dest, data, exclusive=True)
    log.info("Key backup written: %s (sha256=%s)", dest, hashlib.sha256(data).hexdigest()[:16] + "...")
    return dest


def change_passphrase(keyfile: Path, old: str, new: str) -> None:
    """Re-wrap the DEK with a new passphrase. Encrypted data stays valid."""
    _check_passphrase_strength(new)
    dek = load_dek(keyfile, old)
    tmp = keyfile.with_suffix(keyfile.suffix + ".tmp")
    _write_private(tmp, json.dumps(_wrap_dek(dek, new), indent=2).encode(), exclusive=False)
    os.replace(tmp, keyfile)


# --------------------------------------------------------------------------- #
# Streaming AES-256-GCM
# --------------------------------------------------------------------------- #
def encrypt_stream(fin, fout, dek: bytes) -> None:
    """
    Layout: MAGIC | chunk_size(u32) | nonce_prefix(8) | { len(u32) | ciphertext+tag }*
    Each chunk nonce = prefix || counter(u32). AAD = header || last-chunk flag, which
    prevents truncation, reordering and cross-file header substitution.
    """
    aes = AESGCM(dek)
    prefix = os.urandom(8)
    header = MAGIC + struct.pack(">I", CHUNK_SIZE) + prefix
    fout.write(header)

    counter = 0
    chunk = fin.read(CHUNK_SIZE)
    while True:
        nxt = fin.read(CHUNK_SIZE)
        last = not nxt
        if counter >= 2 ** 32:
            raise VaultError("File too large for a single nonce space.")
        nonce = prefix + struct.pack(">I", counter)
        ct = aes.encrypt(nonce, chunk, header + (b"\x01" if last else b"\x00"))
        fout.write(struct.pack(">I", len(ct)))
        fout.write(ct)
        if last:
            return
        chunk, counter = nxt, counter + 1


def decrypt_stream(fin, fout, dek: bytes) -> None:
    aes = AESGCM(dek)
    header = fin.read(HEADER_LEN)
    if len(header) != HEADER_LEN or header[:4] != MAGIC:
        raise VaultError("Not a vault-encrypted file (bad header).")
    (chunk_size,) = struct.unpack(">I", header[4:8])
    prefix = header[8:]

    counter = 0
    while True:
        raw = fin.read(4)
        if len(raw) != 4:
            raise VaultError("Encrypted file is truncated.")
        (n,) = struct.unpack(">I", raw)
        if n < TAG_LEN or n > chunk_size + TAG_LEN:
            raise VaultError("Corrupted chunk length.")
        ct = fin.read(n)
        if len(ct) != n:
            raise VaultError("Encrypted file is truncated.")

        pos = fin.tell()
        last = not fin.read(1)          # EOF after this chunk?
        if not last:
            fin.seek(pos)

        nonce = prefix + struct.pack(">I", counter)
        try:
            pt = aes.decrypt(nonce, ct, header + (b"\x01" if last else b"\x00"))
        except InvalidTag:
            raise VaultError("Authentication failed: wrong key, or data was tampered with/truncated.")
        fout.write(pt)
        if last:
            return
        counter += 1


# --------------------------------------------------------------------------- #
# Directory operations
# --------------------------------------------------------------------------- #
def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(CHUNK_SIZE), b""):
            h.update(block)
    return h.hexdigest()


def _is_within(child: Path, parent: Path) -> bool:
    child, parent = child.resolve(), parent.resolve()
    return child == parent or parent in child.parents


def _prepare_dirs(src: Path, dst: Path, force: bool) -> None:
    if not src.is_dir():
        raise VaultError(f"Source directory not found: {src}")
    if _is_within(dst, src) or _is_within(src, dst):
        raise VaultError("Source and destination must not be inside each other.")
    if dst.exists() and any(dst.iterdir()) and not force:
        raise VaultError(f"Destination {dst} is not empty (use --force to merge/overwrite).")
    dst.mkdir(parents=True, exist_ok=True)


def _atomic_write(dest: Path, writer) -> None:
    """Write via a temp file in the same dir, then atomically rename."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=dest.parent, prefix=".vault-tmp-")
    try:
        with os.fdopen(fd, "wb") as f:
            writer(f)
        os.replace(tmp, dest)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def _walk_files(root: Path):
    """Yield regular files recursively (sorted); symlinks are skipped."""
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames):
            p = Path(dirpath) / name
            if p.is_symlink():
                log.warning("Skipping symlink: %s", p)
                continue
            yield p


def encrypt_directory(src: Path, dst: Path, dek: bytes, force: bool = False) -> dict:
    _prepare_dirs(src, dst, force)
    manifest, total = [], 0
    for path in _walk_files(src):
        rel = path.relative_to(src)
        out = dst / (str(rel) + ENC_SUFFIX)

        def write(f, path=path):
            with open(path, "rb") as fin:
                encrypt_stream(fin, f, dek)

        _atomic_write(out, write)
        size = path.stat().st_size
        manifest.append({"path": rel.as_posix(), "size": size, "sha256": _sha256_file(path)})
        total += size
        log.info("ENCRYPTED  %-40s %10d bytes -> %s", rel.as_posix(), size, out.name)

    blob = json.dumps({"version": 1, "files": manifest}, indent=2).encode()
    _atomic_write(dst / MANIFEST_NAME, lambda f: encrypt_stream(io.BytesIO(blob), f, dek))
    log.info("Encrypted manifest written (%d entries).", len(manifest))
    return {"files": len(manifest), "bytes": total}


def decrypt_directory(src: Path, dst: Path, dek: bytes, force: bool = False) -> dict:
    _prepare_dirs(src, dst, force)

    manifest = None
    mpath = src / MANIFEST_NAME
    if mpath.is_file():
        buf = io.BytesIO()
        with open(mpath, "rb") as f:
            decrypt_stream(f, buf, dek)
        manifest = {e["path"]: e for e in json.loads(buf.getvalue())["files"]}
    else:
        log.warning("No %s found; integrity check against original hashes skipped.", MANIFEST_NAME)

    restored, total, seen = 0, 0, set()
    for path in _walk_files(src):
        if path.name == MANIFEST_NAME and path.parent == src:
            continue
        if not path.name.endswith(ENC_SUFFIX):
            log.warning("Skipping non-vault file: %s", path)
            continue
        rel = path.relative_to(src)
        rel_plain = Path(str(rel)[: -len(ENC_SUFFIX)])
        out = dst / rel_plain
        if not _is_within(out, dst):
            raise VaultError(f"Unsafe path in archive: {rel}")

        def write(f, path=path):
            with open(path, "rb") as fin:
                decrypt_stream(fin, f, dek)

        _atomic_write(out, write)
        size = out.stat().st_size
        status = "OK"
        if manifest is not None:
            entry = manifest.get(rel_plain.as_posix())
            if entry is None:
                status = "NOT-IN-MANIFEST"
            elif entry["size"] != size or entry["sha256"] != _sha256_file(out):
                raise VaultError(f"Integrity check FAILED for {rel_plain}")
            else:
                status = "VERIFIED"
            seen.add(rel_plain.as_posix())
        log.info("DECRYPTED  %-40s %10d bytes [%s]", rel_plain.as_posix(), size, status)
        restored += 1
        total += size

    if manifest is not None:
        missing = set(manifest) - seen
        if missing:
            raise VaultError(f"Files listed in manifest are missing: {sorted(missing)}")
    return {"files": restored, "bytes": total}


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _get_passphrase(env_name="VAULT_PASSPHRASE", prompt="Master passphrase: ", confirm=False) -> str:
    env = os.environ.get(env_name)
    if env:
        return env
    pw = getpass.getpass(prompt)
    if confirm and getpass.getpass("Confirm passphrase: ") != pw:
        raise VaultError("Passphrases do not match.")
    return pw


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="AES-256-GCM directory encryption vault.")
    p.add_argument("--log-file", help="Also write the log to this file.")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="Create a new passphrase-protected key file.")
    s.add_argument("--keyfile", required=True, type=Path)
    s.add_argument("--backup-dir", type=Path, help="Also write a key backup here.")

    for name, helptext in (("encrypt", "Encrypt a directory tree."), ("decrypt", "Decrypt a vault directory.")):
        s = sub.add_parser(name, help=helptext)
        s.add_argument("source", type=Path)
        s.add_argument("destination", type=Path)
        s.add_argument("--keyfile", required=True, type=Path)
        s.add_argument("--force", action="store_true", help="Allow non-empty destination.")

    s = sub.add_parser("backup-key", help="Create a timestamped key file backup.")
    s.add_argument("--keyfile", required=True, type=Path)
    s.add_argument("--backup-dir", required=True, type=Path)

    s = sub.add_parser("change-passphrase", help="Re-wrap the key with a new passphrase.")
    s.add_argument("--keyfile", required=True, type=Path)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    handlers = [logging.StreamHandler(sys.stdout)]
    if args.log_file:
        handlers.append(logging.FileHandler(args.log_file, encoding="utf-8"))
    logging.basicConfig(level=logging.INFO, handlers=handlers, force=True,
                        format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
    try:
        if args.cmd == "init":
            pw = _get_passphrase(prompt="Choose master passphrase: ", confirm=True)
            create_keyfile(args.keyfile, pw)
            log.info("Key file created: %s (permissions 0600)", args.keyfile)
            if args.backup_dir:
                backup_keyfile(args.keyfile, args.backup_dir)
            log.info("IMPORTANT: store the key backup AND passphrase in separate safe places.")
        elif args.cmd in ("encrypt", "decrypt"):
            dek = load_dek(args.keyfile, _get_passphrase())
            fn = encrypt_directory if args.cmd == "encrypt" else decrypt_directory
            res = fn(args.source, args.destination, dek, args.force)
            log.info("DONE: %d files, %d bytes processed.", res["files"], res["bytes"])
        elif args.cmd == "backup-key":
            backup_keyfile(args.keyfile, args.backup_dir)
        elif args.cmd == "change-passphrase":
            old = _get_passphrase("VAULT_PASSPHRASE", "Current passphrase: ")
            new = _get_passphrase("VAULT_NEW_PASSPHRASE", "New passphrase: ", confirm=True)
            change_passphrase(args.keyfile, old, new)
            log.info("Passphrase changed. Existing encrypted data remains readable.")
        return 0
    except VaultError as e:
        log.error("%s", e)
        return 1
    except KeyboardInterrupt:
        log.error("Interrupted.")
        return 130


if __name__ == "__main__":
    sys.exit(main())

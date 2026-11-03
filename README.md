# 🔐 Cryptographic Encryption Vault

A Python command-line tool that **encrypts and decrypts entire directory trees** using
**AES-256-GCM**, with passphrase-protected key management and key-file backups.

## Features

| Requirement | How it is implemented |
|---|---|
| Recursively scan directories | `os.walk` over the full tree, preserving folder structure (symlinks skipped) |
| AES-GCM encryption | AES-256-GCM, streamed in 1 MiB chunks (large files are fine) |
| Master passphrase | Passphrase -> **scrypt** (N=2^15, r=8, p=1) -> key-encryption key |
| Secure key file + backups | Random 256-bit data key wrapped by the passphrase; timestamped `0600` backups |
| No data corruption | Encrypted SHA-256 manifest verifies every restored file; GCM detects tampering/truncation |

### Key-management design (envelope encryption)

```
Passphrase --scrypt+salt--> KEK --AES-GCM wraps--> random DEK (stored in demo.key)
DEK --AES-256-GCM--> every file (.vlt)
```

* Changing your passphrase only re-wraps the DEK. **No files need re-encrypting.**
* The key file is useless without the passphrase; the passphrase is useless without the key file.
* The tool is **non-destructive**: original files are never modified or deleted.

## Setup

Requires **Python 3.9+**.

```bash
git clone https://github.com/<your-username>/cryptographic-encryption-vault.git
cd cryptographic-encryption-vault
python -m venv .venv
# Windows:  .venv\Scripts\activate
# Mac/Linux: source .venv/bin/activate
pip install -r requirements.txt
```

## Quick start (automated demo + proof)

```bash
python demo.py
```

This builds sample data, creates a key + backup, encrypts, decrypts, and confirms the
restored folder is identical. The log is saved to `demo_run.log`.

## Manual usage

```bash
# 1. Create a key file (prompts for a passphrase, min 12 chars) and a backup
python vault.py init --keyfile secrets/my.key --backup-dir key_backups

# 2. Encrypt a directory  (source -> destination)
python vault.py encrypt ./my_folder ./my_folder_encrypted --keyfile secrets/my.key

# 3. Decrypt it back
python vault.py decrypt ./my_folder_encrypted ./my_folder_restored --keyfile secrets/my.key

# Extra key management
python vault.py backup-key --keyfile secrets/my.key --backup-dir key_backups
python vault.py change-passphrase --keyfile secrets/my.key
```

Optional: add `--log-file run.log` (before the command) to save logs, and `--force` to allow a
non-empty destination folder.

For automation you may set the `VAULT_PASSPHRASE` environment variable instead of being
prompted. (The passphrase is intentionally **not** accepted as a CLI argument, since it
would leak into shell history and process lists.)

## Run the tests

```bash
python -m pytest -v
```

13 tests cover round-trip integrity, empty/large/unicode files, wrong passphrase, tampering,
truncation, missing files, passphrase rotation, key backup recovery and the CLI.

## File format

```
"VLT1" | chunk_size (u32) | nonce_prefix (8 B) | repeat{ length (u32) | ciphertext+16B tag }
```
Per-chunk nonce = prefix || counter. The header and a "last chunk" flag are authenticated as
AAD, so reordering, truncation and header swaps are detected.

## Security notes

* **Lose the key file AND its backups, or forget the passphrase = data is unrecoverable.**
  Store backups on separate media from the encrypted data.
* Never commit `*.key`, backups or real data (the `.gitignore` already blocks them).
* File *names* and sizes are visible in the encrypted output; file *contents* and the
  manifest (hashes) are encrypted.
* Educational project: for production secrets, prefer audited tools (age, gpg, VeraCrypt).

## License
MIT

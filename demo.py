#!/usr/bin/env python3
"""
End-to-end demo: creates sample data, encrypts it, restores it, and proves
the restored copy is byte-for-byte identical. Run:  python demo.py
Works on Windows, macOS and Linux. Output is also saved to demo_run.log.
"""
import filecmp
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PASSPHRASE = "Demo-Passphrase-2026!"
ENV = {**os.environ, "VAULT_PASSPHRASE": PASSPHRASE}

SAMPLE, ENC, OUT = ROOT / "sample_data", ROOT / "vault_encrypted", ROOT / "vault_restored"
KEY, BACKUPS = ROOT / "secrets" / "demo.key", ROOT / "key_backups"


def run(*args):
    cmd = [sys.executable, str(ROOT / "vault.py"), "--log-file", str(ROOT / "demo_run.log"), *map(str, args)]
    print("\n$ python vault.py " + " ".join(map(str, args)))
    r = subprocess.run(cmd, env=ENV)
    if r.returncode:
        sys.exit(f"Command failed with exit code {r.returncode}")


def same_tree(a: Path, b: Path) -> bool:
    cmp = filecmp.dircmp(a, b)
    if cmp.left_only or cmp.right_only or cmp.diff_files or cmp.funny_files:
        return False
    # dircmp is shallow by default -> compare contents explicitly
    for f in cmp.common_files:
        if (a / f).read_bytes() != (b / f).read_bytes():
            return False
    return all(same_tree(a / d, b / d) for d in cmp.common_dirs)


def main():
    for p in (SAMPLE, ENC, OUT, KEY.parent, BACKUPS, ROOT / "demo_run.log"):
        shutil.rmtree(p, ignore_errors=True) if p.is_dir() else p.unlink(missing_ok=True)

    # 1. Build sample data
    (SAMPLE / "docs" / "reports").mkdir(parents=True)
    (SAMPLE / "photos").mkdir()
    (SAMPLE / "readme.txt").write_text("Top secret project notes.\n")
    (SAMPLE / "docs" / "budget.csv").write_text("item,cost\nservers,1200\nlicenses,300\n")
    (SAMPLE / "docs" / "reports" / "q3.txt").write_text("Quarterly report " * 1000)
    (SAMPLE / "photos" / "random.bin").write_bytes(os.urandom(3 * 1024 * 1024))  # multi-chunk
    (SAMPLE / "photos" / "empty.dat").write_bytes(b"")
    print(f"Sample data created in {SAMPLE}")

    # 2. Key management: init + backup
    KEY.parent.mkdir(exist_ok=True)
    run("init", "--keyfile", KEY, "--backup-dir", BACKUPS)

    # 3. Encrypt, 4. Decrypt
    run("encrypt", SAMPLE, ENC, "--keyfile", KEY)
    run("decrypt", ENC, OUT, "--keyfile", KEY)

    # 5. Prove no corruption
    ok = same_tree(SAMPLE, OUT)
    print("\n" + "=" * 60)
    print("RESULT: restored directory is IDENTICAL to original" if ok else "RESULT: MISMATCH!")
    print("=" * 60)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()

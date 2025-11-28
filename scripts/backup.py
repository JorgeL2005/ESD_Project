import os
import shutil
from datetime import datetime
from pathlib import Path
import hashlib

BASE_DIR = Path(os.getcwd())
DATA_DIR = BASE_DIR / "data"
KEYS_DIR = BASE_DIR / "keys"
SECRETS_DIR = BASE_DIR / "secrets"
BACKUP_DIR = BASE_DIR / "backups" / datetime.utcnow().strftime("%Y%m%d-%H%M%S")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def copy_with_hash(src_dir: Path, dst_dir: Path) -> list[tuple[str, str]]:
    dst_dir.mkdir(parents=True, exist_ok=True)
    results = []
    for root, _, files in os.walk(src_dir):
        rel_root = Path(root).relative_to(src_dir)
        target_root = dst_dir / rel_root
        target_root.mkdir(parents=True, exist_ok=True)
        for name in files:
            src_path = Path(root) / name
            dst_path = target_root / name
            shutil.copy2(src_path, dst_path)
            results.append((str(dst_path.relative_to(dst_dir)), sha256_file(dst_path)))
    return results


def main():
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    index_lines = []
    if DATA_DIR.exists():
        index_lines += [("data/" + f, h) for f, h in copy_with_hash(DATA_DIR, BACKUP_DIR / "data")]
    if KEYS_DIR.exists():
        index_lines += [("keys/" + f, h) for f, h in copy_with_hash(KEYS_DIR, BACKUP_DIR / "keys")]
    if SECRETS_DIR.exists():
        index_lines += [("secrets/" + f, h) for f, h in copy_with_hash(SECRETS_DIR, BACKUP_DIR / "secrets")]

    index_path = BACKUP_DIR / "index.sha256"
    with index_path.open("w", encoding="utf-8") as idx:
        for rel, hashv in index_lines:
            idx.write(f"{hashv}  {rel}\n")
    print(f"Backup creado en {BACKUP_DIR}")


if __name__ == "__main__":
    main()

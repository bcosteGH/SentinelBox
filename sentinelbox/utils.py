import shutil
from pathlib import Path
import uuid

def new_audit_id() -> str:
    return uuid.uuid4().hex

def prepare_audit_dir(base: Path) -> Path:
    if base.exists():
        shutil.rmtree(base)
    base.mkdir(parents=True, exist_ok=True)
    return base

def reset_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)

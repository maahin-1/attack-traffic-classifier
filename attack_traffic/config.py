"""Read local JSON or safe YAML without changing path resolution semantics."""

import json
from pathlib import Path


def load_config(path: str | Path) -> dict:
    path = Path(path)
    try:
        content = path.read_text(encoding="utf-8")
        if path.suffix.lower() in {".yaml", ".yml"}:
            try:
                import yaml
            except ImportError as exc:
                raise ValueError("YAML configs require PyYAML; use JSON or install the training dependencies") from exc
            try:
                config = yaml.safe_load(content)
            except yaml.YAMLError as exc:
                raise ValueError(f"Invalid YAML config {path}: {exc}") from exc
        else:
            config = json.loads(content)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read config {path}: {exc}") from exc
    if not isinstance(config, dict):
        raise ValueError("Config root must be an object")
    return config

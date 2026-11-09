from __future__ import annotations

import base64
from dataclasses import asdict, dataclass, fields, replace
import json
import os
from pathlib import Path
import secrets
import stat
from typing import Any


DEFAULT_CLIENT_INFO = (
    "<PC> <Windows;6.2(0,0);9200> "
    "<com.apple.AuthKitWin/7.3 (com.apple.iCloud/15.10.0.39)>"
)
DEFAULT_USER_AGENT = "com.apple.AuthKitWin/7.3"


class ConfigError(RuntimeError):
    pass


def default_state_dir() -> Path:
    override = os.environ.get("ANISETTE_ON_WINE_HOME")
    if override:
        return Path(override).expanduser()
    data_home = os.environ.get("XDG_DATA_HOME")
    base = Path(data_home).expanduser() if data_home else Path.home() / ".local" / "share"
    return base / "anisette-on-wine"


@dataclass(frozen=True)
class Config:
    version: int = 1
    wine_binary: str = "wine"
    helper_path: str = ""
    client_info: str = DEFAULT_CLIENT_INFO
    user_agent: str = DEFAULT_USER_AGENT
    routing_info: str = "17106176"
    locale: str = "en_US"
    time_zone: str = "UTC"
    serial_fallback: str = "0"
    apple_support_dir: str = ""
    internet_services_dir: str = ""
    token_key: str = ""

    def __post_init__(self) -> None:
        string_fields = (
            "wine_binary",
            "helper_path",
            "client_info",
            "user_agent",
            "routing_info",
            "locale",
            "time_zone",
            "serial_fallback",
            "apple_support_dir",
            "internet_services_dir",
            "token_key",
        )
        for name in string_fields:
            value = getattr(self, name)
            if not isinstance(value, str):
                raise ConfigError(f"configuration field {name} must be text")
            if len(value) > 4096 or any(ord(character) < 0x20 for character in value):
                raise ConfigError(f"configuration field {name} contains invalid characters")
        for required in (
            "wine_binary",
            "client_info",
            "user_agent",
            "routing_info",
            "locale",
            "time_zone",
            "serial_fallback",
        ):
            if not getattr(self, required):
                raise ConfigError(f"configuration field {required} cannot be empty")
        if not self.routing_info.isdecimal() or not 0 <= int(self.routing_info) <= (2**64 - 1):
            raise ConfigError("routing_info must be an unsigned 64-bit decimal value")

    @classmethod
    def fresh(cls, **changes: Any) -> "Config":
        key = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        return replace(cls(token_key=key), **changes)

    @property
    def token_key_bytes(self) -> bytes:
        try:
            key = base64.b64decode(self.token_key, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise ConfigError("configuration contains an invalid token key") from exc
        if len(key) != 32:
            raise ConfigError("configuration token key must contain 32 bytes")
        return key


def ensure_private_dir(path: Path) -> None:
    path = Path(os.path.abspath(path.expanduser()))
    if path.is_symlink():
        raise ConfigError(f"state path must not be a symbolic link: {path}")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or path.is_symlink():
        raise ConfigError(f"state path is not a real directory: {path}")
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise ConfigError(f"state directory is not owned by the current user: {path}")
    os.chmod(path, 0o700)


def _config_path(state_dir: Path) -> Path:
    return state_dir / "config.json"


def save_config(state_dir: Path, config: Config) -> None:
    ensure_private_dir(state_dir)
    destination = _config_path(state_dir)
    temporary = state_dir / f".config.{os.getpid()}.{secrets.token_hex(6)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(asdict(config), stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
        os.chmod(destination, 0o600)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def load_config(state_dir: Path) -> Config:
    state_dir = Path(os.path.abspath(state_dir.expanduser()))
    ensure_private_dir(state_dir)
    path = _config_path(state_dir)
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise ConfigError(f"not initialized: {path} does not exist") from exc
    if path.is_symlink() or not stat.S_ISREG(info.st_mode):
        raise ConfigError(f"configuration is not a regular file: {path}")
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise ConfigError("configuration is not owned by the current user")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise ConfigError("configuration permissions must be 0600")
    if info.st_size > 64 * 1024:
        raise ConfigError("configuration is unexpectedly large")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError("could not read configuration") from exc
    if not isinstance(raw, dict):
        raise ConfigError("configuration root must be an object")
    allowed = {field.name for field in fields(Config)}
    unknown = set(raw) - allowed
    if unknown:
        raise ConfigError(f"unknown configuration fields: {', '.join(sorted(unknown))}")
    try:
        config = Config(**raw)
    except (TypeError, ValueError) as exc:
        raise ConfigError("configuration fields are invalid") from exc
    if config.version != 1:
        raise ConfigError(f"unsupported configuration version: {config.version}")
    config.token_key_bytes
    return config

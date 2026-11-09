from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import threading
from typing import Any

from .config import Config


class ProviderError(RuntimeError):
    """An error safe to show without exposing helper output."""


class WineAnisetteProvider:
    REQUIRED = ("X-Apple-I-MD", "X-Apple-I-MD-M", "machine_udid")

    def __init__(self, state_dir: Path, config: Config, timeout: float = 30.0):
        self.state_dir = state_dir.expanduser().resolve()
        self.config = config
        self.timeout = timeout
        self._lock = threading.Lock()

    @property
    def prefix(self) -> Path:
        return self.state_dir / "prefix"

    @property
    def helper_path(self) -> Path:
        if self.config.helper_path:
            return Path(self.config.helper_path).expanduser().resolve()
        return Path(__file__).resolve().parents[2] / "bin" / "anisette-helper.exe"

    def _environment(self) -> dict[str, str]:
        env = os.environ.copy()
        env.update(
            {
                "WINEARCH": env.get("ANISETTE_ON_WINE_WINEARCH", "win64"),
                "WINEPREFIX": str(self.prefix),
                "WINEDEBUG": env.get("WINEDEBUG", "-all"),
                "WINEDLLOVERRIDES": env.get("WINEDLLOVERRIDES", "mscoree,mshtml="),
            }
        )
        if self.config.apple_support_dir:
            env["ANISETTE_ON_WINE_APPLE_SUPPORT"] = self.config.apple_support_dir
        if self.config.internet_services_dir:
            env["ANISETTE_ON_WINE_INTERNET_SERVICES"] = self.config.internet_services_dir
        return env

    def _command(self, *arguments: str) -> list[str]:
        wine = shutil.which(self.config.wine_binary)
        if not wine:
            raise ProviderError(f"Wine executable not found: {self.config.wine_binary}")
        helper = self.helper_path
        if not helper.is_file():
            raise ProviderError(f"anisette helper not found: {helper}")
        return [wine, str(helper), *arguments]

    def _discard_helper_logs(self) -> None:
        """Remove AOSKit's per-process diagnostics without touching Wine state."""
        users = self.prefix / "drive_c" / "users"
        try:
            log_directories = users.glob("*/AppData/Local/AppleMigration/Logs/AOSKit")
            for directory in log_directories:
                if directory.is_symlink() or not directory.is_dir():
                    continue
                for path in directory.glob("AOSKit-anisette-helper*.log"):
                    try:
                        if path.is_file() and not path.is_symlink():
                            path.unlink()
                    except OSError:
                        pass
        except OSError:
            pass

    def _invoke(self, *arguments: str) -> dict[str, Any]:
        try:
            completed = subprocess.run(
                self._command(*arguments),
                env=self._environment(),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ProviderError("the Wine helper timed out") from exc
        except OSError as exc:
            raise ProviderError("the Wine helper could not be started") from exc
        finally:
            self._discard_helper_logs()
        if len(completed.stdout) > 64 * 1024 or len(completed.stderr) > 64 * 1024:
            raise ProviderError("the Wine helper produced too much output")
        if completed.returncode != 0:
            raise ProviderError(f"the Wine helper failed with exit code {completed.returncode}")
        try:
            payload = json.loads(completed.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProviderError("the Wine helper returned an invalid response") from exc
        if not isinstance(payload, dict):
            raise ProviderError("the Wine helper response was not an object")
        return payload

    def probe(self) -> dict[str, Any]:
        with self._lock:
            payload = self._invoke("--probe")
        if payload.get("ok") is not True:
            raise ProviderError("AOSKit did not pass its load probe")
        return payload

    def _windows_path(self, path: Path) -> str:
        wine = Path(self._command()[0])
        winepath = wine.with_name("winepath") if wine.is_absolute() else None
        executable = str(winepath) if winepath is not None and winepath.is_file() else shutil.which("winepath")
        if not executable:
            raise ProviderError("winepath was not found beside the configured Wine executable")
        try:
            completed = subprocess.run(
                [executable, "-w", str(path)],
                env=self._environment(),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ProviderError("winepath could not translate the certificate path") from exc
        if completed.returncode != 0 or len(completed.stdout) > 4096:
            raise ProviderError("winepath could not translate the certificate path")
        try:
            translated = completed.stdout.decode("utf-8").strip()
        except UnicodeDecodeError as exc:
            raise ProviderError("winepath returned an invalid certificate path") from exc
        if not translated or "\n" in translated or "\r" in translated:
            raise ProviderError("winepath returned an invalid certificate path")
        return translated

    def install_root(self, certificate: Path) -> None:
        certificate = certificate.expanduser().resolve()
        if not certificate.is_file() or certificate.is_symlink():
            raise ProviderError("the Apple root certificate is not a regular file")
        with self._lock:
            payload = self._invoke("--install-root", self._windows_path(certificate))
        if payload.get("ok") is not True or payload.get("certificate_installed") is not True:
            raise ProviderError("the Apple root certificate was not installed")

    def provision(self) -> None:
        with self._lock:
            payload = self._invoke("--provision")
        if payload.get("ok") is not True or payload.get("provisioned") is not True:
            raise ProviderError("CoreADI machine provisioning did not complete")

    @staticmethod
    def _validated_base64(payload: dict[str, Any], key: str) -> str:
        value = payload.get(key)
        if not isinstance(value, str) or not value or len(value) > 16 * 1024:
            raise ProviderError(f"the Wine helper omitted {key}")
        try:
            decoded = base64.b64decode(value, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise ProviderError(f"the Wine helper returned invalid {key}") from exc
        if not decoded:
            raise ProviderError(f"the Wine helper returned empty {key}")
        return value

    def headers(self) -> dict[str, str]:
        with self._lock:
            payload = self._invoke("--json")
        otp = self._validated_base64(payload, "X-Apple-I-MD")
        machine = self._validated_base64(payload, "X-Apple-I-MD-M")
        device_id = payload.get("machine_udid")
        if not isinstance(device_id, str) or not device_id or len(device_id) > 512:
            raise ProviderError("AOSKit did not return a machine UDID")
        serial = payload.get("serial_number")
        if not isinstance(serial, str) or not serial or len(serial) > 512:
            serial = self.config.serial_fallback
        local_user = payload.get("local_user")
        if not isinstance(local_user, str) or not local_user or len(local_user) > 512:
            # Compatibility fallback for older helpers. Current helpers return
            # the paired Windows identifier persisted with the CoreADI state.
            local_user = base64.b64encode(device_id.encode("utf-8")).decode("ascii")
        routing_info = payload.get("routing_info")
        if (
            not isinstance(routing_info, str)
            or not routing_info.isdecimal()
            or not 0 <= int(routing_info) <= (2**64 - 1)
        ):
            routing_info = self.config.routing_info
        now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        return {
            "X-Apple-I-Client-Time": now,
            "X-Apple-Client-Time": now,
            "X-Apple-I-MD": otp,
            "X-Apple-I-MD-LU": local_user,
            "X-Apple-I-MD-M": machine,
            "X-Apple-I-MD-RINFO": routing_info,
            "X-Apple-I-SRL-NO": serial,
            "X-Apple-I-TimeZone": self.config.time_zone,
            "X-Apple-Locale": self.config.locale,
            "X-MMe-Client-Info": self.config.client_info,
            "X-Mme-Device-Id": device_id,
        }

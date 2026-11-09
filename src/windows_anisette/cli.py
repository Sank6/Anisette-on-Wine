from __future__ import annotations

import argparse
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import urllib.request

from .config import Config, ConfigError, default_state_dir, ensure_private_dir, load_config, save_config
from .provider import ProviderError, WineAnisetteProvider
from .server import ServiceError, require_loopback, serve
from .tokens import ProvisioningTokens


APPLE_ROOT_URL = "https://www.apple.com/appleca/AppleIncRootCertificate.cer"
APPLE_ROOT_SHA256 = "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024"


def _state_dir(value: str | None) -> Path:
    return Path(value).expanduser() if value else default_state_dir()


def _wine_environment(state_dir: Path) -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            # Current iCloud and AOSKit are 64-bit. Keep one persistent win64
            # prefix because it contains the CoreADI machine identity.
            "WINEARCH": env.get("ANISETTE_ON_WINE_WINEARCH", "win64"),
            "WINEPREFIX": str((state_dir / "prefix").resolve()),
            "WINEDEBUG": env.get("WINEDEBUG", "-all"),
            # The Apple stack is native code. Suppress Wine's optional Mono
            # and Gecko bootstrap dialogs so headless first boot cannot stall.
            "WINEDLLOVERRIDES": env.get("WINEDLLOVERRIDES", "mscoree,mshtml="),
        }
    )
    return env


def _run_checked(
    command: list[str],
    env: dict[str, str] | None = None,
    allowed_returncodes: frozenset[int] = frozenset({0}),
) -> int:
    completed = subprocess.run(command, env=env, check=False)
    if completed.returncode not in allowed_returncodes:
        raise RuntimeError(f"command failed with exit code {completed.returncode}: {command[0]}")
    return completed.returncode


def installer_command(wine: str, installer: Path, silent: bool) -> list[str]:
    if installer.suffix.lower() == ".msi":
        command = [wine, "msiexec", "/i", str(installer)]
        if silent:
            command.append("/qn")
        return command
    command = [wine, str(installer)]
    if silent:
        command.append("/quiet")
    return command


def command_build_helper(args: argparse.Namespace) -> int:
    wine_dir = Path(__file__).resolve().parents[2]
    source_dir = wine_dir / "harness"
    build_dir = Path(args.build_dir).expanduser().resolve() if args.build_dir else wine_dir / "build"
    toolchain = source_dir / "cmake" / "mingw64.cmake"
    _run_checked(
        [
            args.cmake,
            "-S",
            str(source_dir),
            "-B",
            str(build_dir),
            f"-DCMAKE_TOOLCHAIN_FILE={toolchain}",
            "-DCMAKE_BUILD_TYPE=Release",
        ]
    )
    _run_checked([args.cmake, "--build", str(build_dir), "--config", "Release"])
    candidates = list(build_dir.rglob("anisette-helper.exe"))
    if len(candidates) != 1:
        raise RuntimeError("build did not produce exactly one anisette-helper.exe")
    output_dir = wine_dir / "bin"
    output_dir.mkdir(mode=0o755, exist_ok=True)
    output = output_dir / "anisette-helper.exe"
    shutil.copy2(candidates[0], output)
    print(f"Built {output}")
    return 0


def command_init(args: argparse.Namespace) -> int:
    state_dir = Path(os.path.abspath(_state_dir(args.state_dir)))
    ensure_private_dir(state_dir)
    config_path = state_dir / "config.json"
    if config_path.exists() and not args.reuse:
        raise ConfigError("state is already initialized; pass --reuse to keep this identity")
    config = load_config(state_dir) if config_path.exists() else Config.fresh(wine_binary=args.wine)
    wine = shutil.which(config.wine_binary)
    if not wine:
        raise RuntimeError(f"Wine executable not found: {config.wine_binary}")
    env = _wine_environment(state_dir)
    if not args.skip_wineboot:
        wineboot = shutil.which("wineboot")
        wine_path = Path(wine)
        if wine_path.is_absolute():
            sibling = wine_path.with_name("wineboot")
            if sibling.is_file() and os.access(sibling, os.X_OK):
                wineboot = str(sibling)
        if not wineboot:
            raise RuntimeError("wineboot was not found")
        _run_checked([wineboot, "--init"], env)
    for installer_value in args.installer:
        installer = Path(installer_value).expanduser().resolve()
        if not installer.is_file() or installer.is_symlink():
            raise RuntimeError(f"installer is not a regular file: {installer}")
        # Windows Installer's ERROR_SUCCESS_REBOOT_REQUIRED (3010) is exposed
        # by Wine as the low POSIX exit byte, 194. The payload is installed;
        # treating that status as failure makes a successful iCloud install
        # look broken.
        status = _run_checked(
            installer_command(wine, installer, args.silent),
            env,
            frozenset({0, 194}),
        )
        if status == 194:
            print(f"Installed {installer.name}; Wine prefix reboot required.")
    if not config_path.exists():
        save_config(state_dir, config)
    print(f"Persistent Wine identity initialized at {state_dir / 'prefix'}")
    print("Run 'anisette-on-wine doctor' before starting the service.")
    return 0


def command_configure(args: argparse.Namespace) -> int:
    state_dir = _state_dir(args.state_dir)
    config = load_config(state_dir)
    changes: dict[str, str] = {}
    for argument, field_name in (
        (args.client_info, "client_info"),
        (args.user_agent, "user_agent"),
        (args.routing_info, "routing_info"),
        (args.locale, "locale"),
        (args.time_zone, "time_zone"),
        (args.serial_fallback, "serial_fallback"),
        (args.helper_path, "helper_path"),
        (args.apple_support_dir, "apple_support_dir"),
        (args.internet_services_dir, "internet_services_dir"),
    ):
        if argument is not None:
            changes[field_name] = argument
    if not changes:
        raise ConfigError("no configuration changes were supplied")
    save_config(state_dir, replace(config, **changes))
    print("Configuration updated; the persistent Wine prefix was not changed.")
    return 0


def command_doctor(args: argparse.Namespace) -> int:
    state_dir = _state_dir(args.state_dir)
    config = load_config(state_dir)
    provider = WineAnisetteProvider(state_dir, config, timeout=args.timeout)
    checks: list[tuple[str, bool, str]] = []
    checks.append(("Wine prefix", provider.prefix.is_dir(), str(provider.prefix)))
    checks.append(("Helper", provider.helper_path.is_file(), str(provider.helper_path)))
    try:
        probe = provider.probe()
        checks.append(("AOSKit load", True, str(probe.get("backend", "aoskit"))))
    except ProviderError as exc:
        checks.append(("AOSKit load", False, str(exc)))
    try:
        headers = provider.headers()
        checks.append(
            (
                "OTP generation",
                True,
                f"received {len(headers['X-Apple-I-MD'])} OTP characters (value hidden)",
            )
        )
        checks.append(("Machine identity", bool(headers["X-Mme-Device-Id"]), "present (value hidden)"))
    except ProviderError as exc:
        checks.append(("OTP generation", False, str(exc)))
    for name, passed, detail in checks:
        print(f"[{'ok' if passed else 'FAIL'}] {name}: {detail}")
    return 0 if all(passed for _, passed, _ in checks) else 1


def _apple_root_certificate(state_dir: Path, supplied: str | None, timeout: float) -> Path:
    if supplied:
        certificate = Path(supplied).expanduser().resolve()
        if not certificate.is_file() or certificate.is_symlink():
            raise RuntimeError(f"certificate is not a regular file: {certificate}")
        encoded = certificate.read_bytes()
    else:
        certificate_dir = state_dir / "certificates"
        ensure_private_dir(certificate_dir)
        certificate = certificate_dir / "AppleIncRootCertificate.cer"
        if certificate.is_symlink():
            raise RuntimeError(f"certificate must not be a symbolic link: {certificate}")
        encoded = certificate.read_bytes() if certificate.is_file() else b""
        if hashlib.sha256(encoded).hexdigest() != APPLE_ROOT_SHA256:
            request = urllib.request.Request(APPLE_ROOT_URL, headers={"User-Agent": "anisette-on-wine/1"})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                encoded = response.read(64 * 1024 + 1)
            if len(encoded) > 64 * 1024:
                raise RuntimeError("the Apple root certificate download was too large")
            if hashlib.sha256(encoded).hexdigest() != APPLE_ROOT_SHA256:
                raise RuntimeError("the Apple root certificate fingerprint did not match Apple")
            certificate.write_bytes(encoded)
            certificate.chmod(0o600)
    if hashlib.sha256(encoded).hexdigest() != APPLE_ROOT_SHA256:
        raise RuntimeError("the Apple root certificate fingerprint did not match Apple")
    return certificate


def command_provision(args: argparse.Namespace) -> int:
    state_dir = Path(os.path.abspath(_state_dir(args.state_dir)))
    config = load_config(state_dir)
    provider = WineAnisetteProvider(state_dir, config, timeout=args.timeout)
    certificate = _apple_root_certificate(state_dir, args.apple_root, args.timeout)
    provider.install_root(certificate)
    provider.provision()
    print("Persistent CoreADI machine provisioning completed and a fresh OTP was verified.")
    return 0


def command_headers(args: argparse.Namespace) -> int:
    state_dir = _state_dir(args.state_dir)
    config = load_config(state_dir)
    provider = WineAnisetteProvider(state_dir, config, timeout=args.timeout)
    json.dump(provider.headers(), sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


def command_serve(args: argparse.Namespace) -> int:
    require_loopback(args.host)
    state_dir = _state_dir(args.state_dir)
    config = load_config(state_dir)
    provider = WineAnisetteProvider(state_dir, config, timeout=args.helper_timeout)
    tokens = ProvisioningTokens(config.token_key_bytes)
    serve(
        args.host,
        args.port,
        provider,
        tokens,
        config.client_info,
        config.user_agent,
        args.tls_cert,
        args.tls_key,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="anisette-on-wine")
    parser.add_argument("--state-dir", help="private state directory")
    subparsers = parser.add_subparsers(dest="command", required=True)

    helper = subparsers.add_parser("build-helper", help="cross-compile the Windows AOSKit helper")
    helper.add_argument("--cmake", default="cmake")
    helper.add_argument("--build-dir")
    helper.set_defaults(function=command_build_helper)

    initialize = subparsers.add_parser("init", help="create and populate the persistent Wine prefix")
    initialize.add_argument("--wine", default="wine")
    initialize.add_argument(
        "--installer",
        action="append",
        default=[],
        help="user-supplied Apple setup executable or extracted MSI",
    )
    initialize.add_argument("--silent", action="store_true", help="append /quiet to each installer")
    initialize.add_argument("--skip-wineboot", action="store_true")
    initialize.add_argument("--reuse", action="store_true", help="keep an existing initialized identity")
    initialize.set_defaults(function=command_init)

    configure = subparsers.add_parser("configure", help="update non-secret backend metadata")
    configure.add_argument("--client-info")
    configure.add_argument("--user-agent")
    configure.add_argument("--routing-info")
    configure.add_argument("--locale")
    configure.add_argument("--time-zone")
    configure.add_argument("--serial-fallback")
    configure.add_argument("--helper-path")
    configure.add_argument("--apple-support-dir")
    configure.add_argument("--internet-services-dir")
    configure.set_defaults(function=command_configure)

    doctor = subparsers.add_parser("doctor", help="validate Wine, AOSKit, and OTP generation")
    doctor.add_argument("--timeout", type=float, default=30.0)
    doctor.set_defaults(function=command_doctor)

    provision = subparsers.add_parser(
        "provision",
        help="install Apple's verified root CA and provision the persistent CoreADI identity",
    )
    provision.add_argument("--apple-root", help="use a local AppleIncRootCertificate.cer")
    provision.add_argument("--timeout", type=float, default=60.0)
    provision.set_defaults(function=command_provision)

    headers = subparsers.add_parser("headers", help="print one fresh header set to stdout")
    headers.add_argument("--timeout", type=float, default=30.0)
    headers.set_defaults(function=command_headers)

    server = subparsers.add_parser("serve", help="run the loopback anisette service")
    server.add_argument("--host", default="127.0.0.1")
    server.add_argument("--port", type=int, default=6969)
    server.add_argument("--helper-timeout", type=float, default=30.0)
    server.add_argument("--tls-cert")
    server.add_argument("--tls-key")
    server.set_defaults(function=command_serve)
    return parser


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.function(args))
    except KeyboardInterrupt:
        return 130
    except (ConfigError, ProviderError, ServiceError, RuntimeError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

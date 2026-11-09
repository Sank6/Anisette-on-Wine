# anisette-on-wine

`anisette-on-wine` runs a local anisette service using the Windows iCloud
libraries under Wine. It provides the legacy and v3 anisette endpoints on
localhost while keeping one persistent Wine identity.

Apple's software is not included. You must supply the `iCloud` directory from
the Microsoft Store release of iCloud 15.10.39 (x64), including
`CoreFoundation.dll`, `AOSKit.dll`, `CoreADI64.dll`, and their bundled
dependencies.

## Requirements

- Python 3.10+
- 64-bit Wine
- CMake and an x86_64 MinGW-w64 C++ compiler
- Microsoft Store iCloud 15.10.39 (x64), extracted to a private directory

## Usage

Build the Windows helper:

```sh
./anisette-on-wine build-helper
```

Create a persistent Wine prefix and point the service at the extracted iCloud
directory. Wine paths use a `Z:` prefix for files on the Linux filesystem:

```sh
./anisette-on-wine init
./anisette-on-wine configure \
  --apple-support-dir 'Z:\absolute\path\to\iCloud' \
  --internet-services-dir 'Z:\absolute\path\to\iCloud'
```

Provision the identity, check it, and start the service:

```sh
./anisette-on-wine provision
./anisette-on-wine doctor
./anisette-on-wine serve --port 6969
```

The service listens on `127.0.0.1` by default and exposes `GET /`,
`GET /healthz`, `GET /v3/client_info`, `GET /v3/provisioning_session`, and
`POST /v3/get_headers`.

State is stored in `~/.local/share/anisette-on-wine`. Keep this directory
private and backed up: it contains the persistent device identity. Set
`ANISETTE_ON_WINE_HOME` to use a different location.

Do not expose the service publicly or commit Apple DLLs, generated binaries,
or local state.

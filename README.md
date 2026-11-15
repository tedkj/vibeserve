# VibeServe

TFTP, syslog and a folder over HTTP, all off when you close it.

The field engineer's server kit for firmware upgrades, config pushes and turn-ups, in one window:

- **TFTP server** with the options devices ask for (block size, window size, timeout, transfer
  size), for firmware and configs.
- **Syslog receiver** over UDP and TCP, reading RFC 5424, RFC 3164 and the vendors' variants, with
  a filter, Pause and an optional daily log file.
- **HTTP folder server** for one folder: listings, downloads with resume, and uploads when you
  turn them on.

Each server has its own switch, port and address to listen on, and a log of who fetched or sent
what. Every server stops when the window closes; nothing runs as a service, and no DHCP or DNS
server is in here to surprise a customer's network.

## What it touches on your PC

- **One root folder** for TFTP and HTTP, `%USERPROFILE%\VibeServe` unless you pick another. Every
  request goes through one path check: nothing outside the root, no hidden or system files, and a
  link or junction that leads out is refused before a byte is sent.
- **Writes are off** at every start, each with its own switch. When on, they only create new files
  (an existing name is refused), and a failed transfer removes only its own temporary file.
- **Windows Firewall:** a per-user app can't add a firewall rule itself. Turning on the first
  server offers one Windows prompt for a short-lived helper that adds allow rules for VibeServe's
  own ports, for your local subnet only, and removes them again when the servers stop or the app
  closes. Say no and the servers still run; other devices may just be blocked. The app itself never
  runs elevated.
- Its settings live in `%APPDATA%\com.tedkj.vibeserve`. The daily syslog files, when you turn
  them on, go to `%LOCALAPPDATA%\com.tedkj.vibeserve\syslog` or a folder you pick.

## What it connects to

Nothing on its own: it listens for the devices that talk to it, on the addresses and ports you
turn on. The one request it makes itself is About's "Check this install", when you press it: that
fetches the signed release list from getvibeware.com to compare your copy with the published
release. To check the installer's code signature, Windows itself may fetch certificates from
Windows Update and Certum (who issued the certificate).

## Download

Get the installer from [Releases](https://github.com/tedkj/vibeserve/releases) or
[getvibeware.com](https://getvibeware.com). It installs for your user only, without admin rights.
The installer, VibeServe.exe and its uninstaller are code signed by "Open Source Developer Ted
Kenneth Johansen" (right-click › Properties › Digital Signatures). Compare the installer's SHA-256
with the one in `SHA256SUMS.txt` on the release page:

```powershell
Get-FileHash .\VibeServe_0.1.0-preview_x64-setup.exe
```

## Building from source

You need a current stable Rust toolchain on Windows (the MSVC target).

```sh
cargo build --release --locked
```

The app is then at `target\release\vibeserve.exe`.

### Building the installer

`installer\build.ps1` builds the app and its installer,
`target\release\bundle\VibeServe_<version>_x64-setup.exe`. It needs the official NSIS 3.13:
download `nsis-3.13.zip` from SourceForge (SHA-256
`ba63dffc4410ee89193e1cb5a41989991bd77c61068da17e3156d136b7b0b3d8`) and unpack it to
`_tools\nsis-3.13` in the folder that holds this repository (`..\_tools\nsis-3.13`). The script
checks that whole folder against a pinned hash before it runs anything from it.
`installer\notices.ps1` writes `THIRD-PARTY-NOTICES.txt` for each build (every crate the app
links, with its licence text), and the installer puts it and `LICENSE` next to the app.

## License

[AGPL-3.0](LICENSE) (AGPL-3.0-only). Use it, change it, share it. If you hand out a changed
version, or run one as a service for other people, you share your changes under the same license.
Slint is used under its GPLv3 option. `vendor/` holds Slint's `i-slint-core` 1.18.1 with one small
repaint fix; `vendor/README.md` says what changed and why.

Made in Norway by Ted K. Johansen.

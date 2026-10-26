<h1 align="center">iph — iOS IPA Helper</h1>

<p align="center">
  Install and extract <code>.ipa</code> files from <b>jailbroken and non-jailbroken</b> iOS devices, from one command line.
</p>

<p align="center">
  <a href="https://github.com/Mrcyberwarri0r/IPA-extracter/actions"><img src="https://github.com/Mrcyberwarri0r/IPA-extracter/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/python-3.8%2B-blue" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey" alt="Platform">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License">
</p>

---

`iph` wraps the best tools in the iOS tooling ecosystem — [Frida](https://frida.re),
[pymobiledevice3](https://github.com/doronz88/pymobiledevice3),
[libimobiledevice](https://libimobiledevice.org) and [ipatool](https://github.com/majd/ipatool)
— behind one consistent CLI, and picks the right backend for the device in front of it.

```console
$ iph devices
00008130-00124DC90A62001C  iPhone 15 Pro  iPhone16,1  iOS 18.7.2  usb

$ iph apps
com.burbn.instagram   453.0.0   Instagram
net.whatsapp.WhatsApp 26.41.74  WhatsApp
...

$ iph extract com.example.myapp        # → decrypted, repackaged .ipa (Frida)
$ iph extract com.example.app --method appstore   # → download from the App Store
$ iph install ./MyApp.ipa              # → install a signed .ipa
```

## Features

- 📱 **Install** a signed IPA to any device (jailbroken or not).
- 🔓 **Extract + decrypt** a live app into a clean, installable IPA using an in-memory
  FairPlay decryption agent — **bridge-free, works on Frida 16 and 17+**.
- ☁️ **Download** IPAs from the App Store with your own Apple ID.
- 🔌 **Auto-selects backends** (pymobiledevice3 → libimobiledevice) and **auto-mounts the
  Developer Disk Image** on iOS 17+.
- 🧪 Clear, actionable errors instead of raw stack traces.

## What works where

| Capability                                       | Jailbroken      | Non-jailbroken              |
|--------------------------------------------------|:---------------:|:---------------------------:|
| List devices / apps                              | ✅              | ✅                          |
| **Install** a signed IPA                         | ✅              | ✅                          |
| **Extract → decrypted IPA** (Frida)              | ✅ any app      | ⚠️ apps you signed only ¹   |
| **Download** encrypted IPA (`--method appstore`) | ✅              | ✅                          |

> ¹ On a non-jailbroken device, Frida attaches through Apple's Developer Disk Image. That
> path only reaches apps carrying the `get-task-allow` entitlement — i.e. apps **you**
> signed (development / ad-hoc / sideloaded). App Store apps are not debuggable there, so
> they **cannot be decrypted without a jailbreak**. For those, use `--method appstore` to
> pull Apple's (still-encrypted) IPA, or extract on a jailbroken device. `iph` tells you
> this clearly if you try.

## Requirements

- **macOS or Linux**, Python **3.8+**
- A USB cable and a device you have **trusted** (`Trust This Computer`)
- Optional CLI helpers (install via Homebrew):

  ```bash
  brew install libimobiledevice ideviceinstaller ipatool sshpass
  ```

- For **extraction on a jailbroken device**: `frida-server` running as root (install the
  **Frida** package from Sileo/Cydia/Zebra).
- For **non-jailbroken iOS 16+**: enable *Developer Mode*
  (Settings → Privacy & Security → Developer Mode) and keep the device unlocked.

## Installation

**Option 1 — pipx (recommended, isolated):**
```bash
pipx install git+https://github.com/Mrcyberwarri0r/IPA-extracter
iph doctor
```

**Option 2 — pip:**
```bash
pip install git+https://github.com/Mrcyberwarri0r/IPA-extracter
```

**Option 3 — from source with a bundled venv:**
```bash
git clone https://github.com/Mrcyberwarri0r/IPA-extracter
cd IPA-extracter
./install.sh
./bin/iph doctor          # or: ln -s "$PWD/bin/iph" /opt/homebrew/bin/iph
```

Run `iph doctor` any time to see which backends and devices are available.

## Usage

### Devices & apps
```bash
iph devices                         # UDID, name, model, iOS, connection
iph apps                            # user apps (--all for system apps, --json for scripting)
iph --udid <UDID> apps              # select a device when several are attached
```

### Install
```bash
iph install ./App.ipa               # install, or upgrade in place
iph install ./App.ipa --upgrade
```
The IPA must already be signed with something the device accepts (App Store, a
development/ad-hoc cert, or enterprise). `iph` does not sign — it installs and reports
exactly why a device rejected an invalid IPA. Backends: **pymobiledevice3** → **ideviceinstaller**.

### Extract — Frida (decrypted IPA)
Decrypts the app in memory and repackages a clean, installable `.ipa`.
```bash
iph extract com.example.app                   # by bundle id
iph extract Instagram                          # by display name
iph extract com.example.app -o ./out/MyApp.ipa
iph extract com.example.app --attach           # attach to a running instance
```

### Extract — App Store download
```bash
ipatool auth login -e you@example.com          # once; interactive 2FA
iph extract com.example.app --method appstore -o ./downloads
```
Downloads the IPA Apple would deliver to your account. It is **FairPlay-encrypted** (as
all App Store IPAs are); decryption still requires a Frida dump on a jailbroken device.

## How Frida extraction works

App Store binaries encrypt their `__TEXT` region (FairPlay, `cryptid=1`). The OS decrypts
those pages in RAM when the app runs. The bundled agent ([`iph/scripts/dump.js`](iph/scripts/dump.js)):

1. Spawns (or attaches to) the target so its binaries map and decrypt.
2. Reads the decrypted pages back from the live process.
3. Rewrites `LC_ENCRYPTION_INFO(_64)` to `cryptid=0` and patches the file.
4. Pulls the whole bundle and repackages `Payload/<App>.app/…` into a `.ipa`.

The agent uses only core Frida APIs (`Process`, `Module`, `Memory`, `File`) plus libc —
**no `frida-objc-bridge`** — so it runs unchanged on Frida 16 and 17+.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `no iOS device detected` | Connect USB, unlock, tap **Trust**. Check `iph devices`. |
| `device is locked` (DDI mount) | Unlock the device and keep it on the Home screen. |
| `enable Developer Mode` | Settings → Privacy & Security → Developer Mode → on, reboot. |
| `cannot instrument … not debuggable` | Non-jailbroken + App Store app. Use `--method appstore`, or a jailbroken device. |
| `ipatool is not signed in` | `ipatool auth login -e <apple-id>` |
| Frida extract fails on a jailbroken device | Ensure `frida-server` is running as root and matches your Frida version (`frida --version`). |

## Development

```bash
python -m unittest -v tests.test_offline     # offline tests, no device needed
python -m compileall iph
```
Tests are dependency-free and run in CI on Python 3.9–3.12.

## Project layout

```
bin/iph              launcher (uses the project venv)
iph/cli.py           argparse CLI + dispatch
iph/device.py        device discovery, info, DDI auto-mount
iph/install.py       install (pymobiledevice3 → ideviceinstaller)
iph/extract.py       strategy dispatch + installed-app listing + App Store download
iph/frida_dump.py    Frida driver: spawn/attach, pull bundle, repackage
iph/scripts/dump.js  Frida agent: in-memory Mach-O decryption (bridge-free)
iph/ssh.py           SSH/SCP + iproxy transport for jailbroken devices
tests/               offline unit tests
```

## ⚖️ Authorized use & disclaimer

This tool is for **lawful, authorized** use only: your own devices and development builds,
security research on apps you are permitted to analyze, and personal backups of apps you
have licensed. You are responsible for complying with the laws that apply to you, the App
Store terms, and each app's license. **Do not** redistribute other people's decrypted
apps — that is copyright infringement. The software is provided "as is", without warranty;
the author accepts no liability for misuse. See [LICENSE](LICENSE).

## Credits

Built on the shoulders of [Frida](https://frida.re),
[pymobiledevice3](https://github.com/doronz88/pymobiledevice3),
[libimobiledevice](https://libimobiledevice.org), and
[ipatool](https://github.com/majd/ipatool). The decryption approach follows the
well-established technique pioneered by tools like `frida-ios-dump`.

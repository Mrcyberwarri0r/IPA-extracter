# iph — iOS IPA Helper

Install and extract `.ipa` files from **jailbroken and non-jailbroken** iOS
devices from the macOS command line. One tool, several backends, chosen
automatically for the device in front of it.

```
iph doctor                      # check environment + list devices
iph devices                     # list connected devices
iph apps                        # list installed apps on a device
iph install app.ipa             # install a signed IPA
iph extract <bundle-id|name>    # decrypt a live app → clean .ipa (Frida)
iph extract <bundle-id> --method appstore   # download the IPA from the App Store
```

## What works where

| Capability                                   | Jailbroken | Non-jailbroken |
|-----------------------------------------------|:---------:|:--------------:|
| List devices / apps                           | ✅ | ✅ |
| **Install** a signed IPA                      | ✅ | ✅ |
| **Extract** → decrypted IPA (Frida)           | ✅ any app | ⚠️ debuggable apps only¹ |
| **Download** encrypted IPA (`--method appstore`) | ✅ | ✅ |

¹ On a non-jailbroken device Frida attaches through the Developer Disk Image
(Apple's debug path). That path only reaches apps carrying the `get-task-allow`
entitlement — i.e. apps **you** signed (development / ad-hoc). App Store apps are
not debuggable there, so they cannot be decrypted without a jailbreak. For those,
use `--method appstore` to pull Apple's (still-encrypted) IPA, or extract on a
jailbroken device.

## Install

```bash
./install.sh          # creates .venv, installs frida + pymobiledevice3
# optional CLI helpers used by some features:
brew install libimobiledevice ideviceinstaller ipatool sshpass
# put it on PATH:
ln -s "$PWD/bin/iph" /opt/homebrew/bin/iph
```

Run `iph doctor` to see which backends are available.

## Usage

### Devices & apps
```bash
iph devices                       # UDID, name, model, iOS, connection
iph apps                          # user apps (add --all for system apps, --json)
iph --udid <UDID> apps            # pick a device when several are attached
```

### Install
```bash
iph install path/to/App.ipa                 # install (or upgrade in place)
iph --udid <UDID> install App.ipa --upgrade
```
The IPA must already be signed with something the device accepts (App Store,
a development/ad-hoc cert, or enterprise). `iph` does not sign; it installs and
reports exactly why the device rejected an unsigned/invalid IPA.

Backends, tried in order: **pymobiledevice3** (great on iOS 17+), then
**ideviceinstaller**.

### Extract — Frida (decrypted IPA)
Decrypts the app in memory and repackages a clean, installable `.ipa`.

```bash
iph extract com.example.app                 # by bundle id
iph extract Instagram                        # by display name
iph extract com.example.app -o ./out/MyApp.ipa
iph extract com.example.app --attach         # attach to a running instance
```

Requirements:
- **Jailbroken:** `frida-server` running as root (install the Frida package from
  your bootstrap's repo). Works for any installed app.
- **Non-jailbroken (iOS 16+):** enable *Developer Mode* (Settings → Privacy &
  Security → Developer Mode), keep the device **unlocked**. `iph` mounts the
  Developer Disk Image automatically. Reaches only developer-signed apps (see ¹).

### Extract — App Store download
```bash
ipatool auth login -e you@example.com        # once; interactive 2FA
iph extract com.example.app --method appstore -o ./downloads
```
Downloads the IPA Apple would deliver to your account. It is FairPlay-encrypted
(as all App Store IPAs are); decryption still requires a Frida dump on a capable
device.

## How Frida extraction works

App Store binaries have an encrypted `__TEXT` region (FairPlay, `cryptid=1`).
The OS decrypts those pages in RAM when the app runs. The bundled agent
(`iph/scripts/dump.js`) reads the decrypted pages back from the live process,
rewrites `LC_ENCRYPTION_INFO(_64)` to `cryptid=0`, patches the file, and the
driver repackages the full bundle into `Payload/<App>.app/…` as a `.ipa`.

## Layout

```
bin/iph              launcher (uses the project venv)
iph/cli.py           argparse CLI + dispatch
iph/device.py        device discovery, info, DDI auto-mount
iph/install.py       install (pymobiledevice3 → ideviceinstaller)
iph/extract.py       strategy dispatch + installed-app listing
iph/frida_dump.py    Frida driver: spawn/attach, pull, repackage
iph/scripts/dump.js  Frida agent: in-memory Mach-O decryption
iph/ssh.py           SSH/SCP + iproxy transport for jailbroken devices
```

## Authorized use

Use this only on devices and apps you own or are explicitly authorized to test
(your own development builds, security research on apps you have permission to
analyze, personal backups of apps you have licensed). Respect app licenses and
the laws that apply to you. Redistributing someone else's decrypted app is
copyright infringement.

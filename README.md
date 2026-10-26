# iph — iOS IPA Helper

Install and extract `.ipa` files from jailbroken and non-jailbroken iOS devices, from
the command line. It wraps the tools you'd otherwise juggle by hand — Frida,
pymobiledevice3, libimobiledevice and ipatool — and picks the right one for the device
that's plugged in.

```
$ iph devices
00008130-00124DC90A62001C  iPhone 15 Pro  iPhone16,1  iOS 18.7.2  usb

$ iph apps
com.burbn.instagram   453.0.0   Instagram
net.whatsapp.WhatsApp 26.41.74  WhatsApp
...

$ iph extract com.example.myapp                  # decrypt a live app -> clean .ipa
$ iph extract com.example.app --method appstore  # download from the App Store
$ iph install ./MyApp.ipa                        # install a signed .ipa
```

## What works where

| Capability                                       | Jailbroken   | Non-jailbroken            |
|--------------------------------------------------|:------------:|:-------------------------:|
| List devices / apps                              | yes          | yes                       |
| Install a signed IPA                             | yes          | yes                       |
| Extract + decrypt an installed app (Frida)       | yes, any app | only apps you signed¹     |
| Download the IPA from the App Store              | yes          | yes                       |

¹ On a stock device Frida attaches through Apple's Developer Disk Image, which only lets
you touch apps that carry the `get-task-allow` entitlement — i.e. apps you built or
sideloaded yourself. App Store apps aren't debuggable there and can't be decrypted without
a jailbreak; use `--method appstore` for those, or extract on a jailbroken device.

## Requirements

- macOS or Linux, Python 3.8+
- A device trusted over USB (`Trust This Computer`)
- Homebrew helpers:

  ```
  brew install libimobiledevice ideviceinstaller ipatool sshpass
  ```

- Jailbroken extraction: `frida-server` running on the device (install the Frida package
  from Sileo/Zebra).
- Non-jailbroken, iOS 16+: turn on Developer Mode (Settings → Privacy & Security →
  Developer Mode) and keep the device unlocked.

## Install

```
git clone https://github.com/Mrcyberwarri0r/IPA-extracter
cd IPA-extracter
./install.sh
./bin/iph doctor
```

Or install it as a command with pip / pipx:

```
pipx install git+https://github.com/Mrcyberwarri0r/IPA-extracter
```

`iph doctor` shows which backends and devices are available.

## Usage

Devices and apps:

```
iph devices
iph apps                 # --all for system apps, --json for scripting
iph --udid <UDID> apps   # when more than one device is attached
```

Install a signed IPA (it has to be signed with something the device accepts — App Store,
a development/ad-hoc cert, or enterprise; this doesn't sign for you):

```
iph install ./App.ipa
iph install ./App.ipa --upgrade
```

Extract and decrypt a live app into a clean, installable IPA:

```
iph extract com.example.app
iph extract Instagram
iph extract com.example.app -o ./out/MyApp.ipa
iph extract com.example.app --attach      # attach instead of spawning
```

Download an IPA from the App Store (encrypted, as Apple ships it):

```
ipatool auth login -e you@example.com
iph extract com.example.app --method appstore -o ./downloads
```

## How the decryption works

App Store binaries encrypt their `__TEXT` region (FairPlay, `cryptid=1`). The OS decrypts
those pages in memory when the app runs. The Frida agent in `iph/scripts/dump.js` reads
the decrypted pages back from the running process, rewrites `LC_ENCRYPTION_INFO(_64)` so
`cryptid=0`, pulls the whole bundle, and repackages it into `Payload/<App>.app` as a
`.ipa`.

The agent sticks to core Frida APIs (`Process`, `Module`, `Memory`, `File`) plus a couple
of libc calls, so it runs on both Frida 16 and 17 without a compile step.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `no iOS device detected` | Connect over USB, unlock, tap Trust. Check `iph devices`. |
| `device is locked` | Unlock the device and keep it on the Home screen. |
| `enable Developer Mode` | Settings → Privacy & Security → Developer Mode, then reboot. |
| `cannot instrument … not debuggable` | Stock device + App Store app. Use `--method appstore`, or a jailbroken device. |
| `ipatool is not signed in` | `ipatool auth login -e <apple-id>` |
| Frida extract fails on a jailbroken device | Make sure `frida-server` is running and matches your Frida version. |

## Development

```
python -m unittest -v tests.test_offline
python -m compileall iph
```

Tests have no third-party dependencies and run in CI on Python 3.9–3.12.

## Notes on use

Use this on devices and apps you own or are allowed to test — your own builds, security
research you're authorized to do, backups of apps you've licensed. Don't redistribute
other people's decrypted apps. See [LICENSE](LICENSE).

Built on [Frida](https://frida.re),
[pymobiledevice3](https://github.com/doronz88/pymobiledevice3),
[libimobiledevice](https://libimobiledevice.org) and
[ipatool](https://github.com/majd/ipatool).

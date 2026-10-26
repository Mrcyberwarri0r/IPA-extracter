"""Command-line interface for iph."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import __version__, device as device_mod, extract as extract_mod, install as install_mod, utils
from .utils import IphError


def _add_udid(p: argparse.ArgumentParser) -> None:
    p.add_argument("-u", "--udid", help="target device UDID (or a unique prefix)")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="iph",
        description="Install and extract IPA files from jailbroken and "
                    "non-jailbroken iOS devices.",
    )
    p.add_argument("--version", action="version", version=f"iph {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("doctor", help="check environment and available backends")

    sp = sub.add_parser("devices", help="list connected iOS devices")

    sp = sub.add_parser("apps", help="list installed apps on a device")
    _add_udid(sp)
    sp.add_argument("--all", action="store_true", help="include system apps")
    sp.add_argument("--json", action="store_true", help="machine-readable output")

    sp = sub.add_parser("install", help="install a (signed) IPA onto a device")
    _add_udid(sp)
    sp.add_argument("ipa", help="path to the .ipa file")
    sp.add_argument("--upgrade", action="store_true", help="upgrade if already installed")

    sp = sub.add_parser("extract", help="extract/download an IPA")
    _add_udid(sp)
    sp.add_argument("target", help="bundle id or app name (frida); bundle id (appstore)")
    sp.add_argument("-o", "--output", help="output .ipa path or directory", default=None)
    sp.add_argument("--method", choices=["frida", "appstore"], default="frida",
                    help="frida = decrypt a live app (default); appstore = download via ipatool")
    sp.add_argument("--attach", action="store_true",
                    help="attach to a running instance instead of spawning (frida)")
    sp.add_argument("--apple-id", help="Apple ID email for appstore method")

    return p


def cmd_doctor(_args) -> int:
    checks = [
        ("pymobiledevice3", "modern install + app listing (iOS 17+)"),
        ("ideviceinstaller", "install + app listing (libimobiledevice)"),
        ("idevice_id", "USB device discovery"),
        ("ideviceinfo", "device info"),
        ("iproxy", "USB port forwarding for SSH"),
        ("ipatool", "App Store downloads (appstore method)"),
        ("sshpass", "password SSH to jailbroken devices"),
    ]
    print("Backends / tools:")
    for name, why in checks:
        path = utils.which(name)
        mark = "✓" if path else "✗"
        print(f"  [{mark}] {name:<18} {why}")
        if path:
            print(f"        {path}")
    try:
        import frida
        print(f"  [✓] frida (python)     in-memory decryption  ({frida.__version__})")
    except ImportError:
        print("  [✗] frida (python)     in-memory decryption  (pip install frida)")

    print("\nDevices:")
    try:
        devs = device_mod.list_devices()
        if not devs:
            print("  (none connected)")
        for d in devs:
            print(f"  - {d.label()}  via {d.connection}")
    except IphError as e:
        print(f"  error: {e}")
    return 0


def cmd_devices(_args) -> int:
    devs = device_mod.list_devices()
    if not devs:
        utils.warn("no devices connected.")
        return 1
    for d in devs:
        print(f"{d.udid}\t{d.name}\t{d.product_type}\tiOS {d.ios_version}\t{d.connection}")
    return 0


def cmd_apps(args) -> int:
    dev = device_mod.resolve(args.udid)
    utils.info(f"device: {dev.label()}")
    apps = extract_mod.list_installed_apps(dev, user_only=not args.all)
    if args.json:
        import json
        print(json.dumps([a.__dict__ for a in apps], indent=2))
        return 0
    if not apps:
        utils.warn("no apps found.")
        return 0
    width = max((len(a.identifier) for a in apps), default=10)
    for a in apps:
        print(f"{a.identifier:<{width}}  {a.version:<10}  {a.name}")
    utils.info(f"{len(apps)} app(s)")
    return 0


def cmd_install(args) -> int:
    dev = device_mod.resolve(args.udid)
    install_mod.install(args.ipa, dev, upgrade=args.upgrade)
    return 0


def cmd_extract(args) -> int:
    if args.method == "appstore":
        out_dir = args.output or "."
        import os
        if out_dir.lower().endswith(".ipa"):
            out_dir = os.path.dirname(out_dir) or "."
        extract_mod.extract_appstore(args.target, out_dir, apple_id=args.apple_id)
        return 0

    # frida
    out = args.output
    if not out:
        safe = args.target.replace("/", "_")
        out = f"{safe}.ipa"
    elif out.endswith("/") or (__import__("os").path.isdir(out)):
        import os
        safe = args.target.replace("/", "_")
        out = os.path.join(out, f"{safe}.ipa")
    extract_mod.extract_frida(args.target, out, udid=args.udid, attach=args.attach)
    return 0


_DISPATCH = {
    "doctor": cmd_doctor,
    "devices": cmd_devices,
    "apps": cmd_apps,
    "install": cmd_install,
    "extract": cmd_extract,
}


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return _DISPATCH[args.command](args)
    except IphError as e:
        utils.err(str(e))
        return 1
    except KeyboardInterrupt:
        utils.err("interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())

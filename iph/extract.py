"""Extraction strategies and installed-app listing.

Strategies
----------
frida     Decrypt a live installed app in memory and repackage it as a clean
          .ipa. Needs Frida on the device: frida-server on a jailbroken device,
          or an app bundled with the Frida gadget. Works on jailbroken and,
          where a gadget is present, non-jailbroken devices.
appstore  Download the IPA straight from the App Store with ipatool using your
          own Apple ID. No device needed; the download is FairPlay-encrypted,
          exactly as Apple delivers it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import List, Optional

from . import frida_dump, utils
from .device import Device
from .utils import IphError


@dataclass
class InstalledApp:
    identifier: str
    name: str = "?"
    version: str = "?"
    app_type: str = "?"  # User | System


def list_installed_apps(dev: Device, *, user_only: bool = True) -> List[InstalledApp]:
    """List apps on a device via pymobiledevice3, falling back to ideviceinstaller."""
    apps: List[InstalledApp] = []

    pmd3 = utils.which("pymobiledevice3")
    if pmd3:
        cmd = [pmd3, "apps", "list", "--udid", dev.udid,
               "-t", "User" if user_only else "Any"]
        proc = utils.run(cmd, capture=True, check=False)
        raw = (proc.stdout or "").strip()
        if raw:
            try:
                data = json.loads(raw)
                for ident, meta in data.items():
                    apps.append(InstalledApp(
                        identifier=ident,
                        name=meta.get("CFBundleDisplayName") or meta.get("CFBundleName", "?"),
                        version=meta.get("CFBundleShortVersionString", "?"),
                        app_type=meta.get("ApplicationType", "?"),
                    ))
                return sorted(apps, key=lambda a: a.name.lower())
            except json.JSONDecodeError:
                pass

    idev = utils.which("ideviceinstaller")
    if idev:
        list_cmd = [idev, "-u", dev.udid, "list", "--user" if user_only else "--all"]
        proc = utils.run(list_cmd, capture=True, check=False)
        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            if not line or line.lower().startswith("total") or " - " not in line:
                continue
            # Format: <bundleid>, "<version>", "<name>"
            parts = [p.strip().strip('"') for p in line.split(",")]
            if parts:
                apps.append(InstalledApp(
                    identifier=parts[0],
                    version=parts[1] if len(parts) > 1 else "?",
                    name=parts[2] if len(parts) > 2 else parts[0],
                    app_type="User",
                ))
        if apps:
            return sorted(apps, key=lambda a: a.name.lower())

    raise IphError("could not list installed apps (need pymobiledevice3 or ideviceinstaller).")


def extract_frida(target: str, out_path: str, *, udid: Optional[str], attach: bool) -> str:
    return frida_dump.dump(target, out_path, udid=udid, attach=attach)


def _ipatool_account() -> Optional[str]:
    """Return the logged-in Apple ID, or None if not authenticated."""
    ipatool = utils.which("ipatool")
    if not ipatool:
        return None
    proc = utils.run([ipatool, "auth", "info", "--format", "json"], capture=True, check=False)
    raw = (proc.stdout or "").strip()
    if proc.returncode == 0 and raw:
        try:
            data = json.loads(raw)
            return data.get("name") or data.get("email") or "logged-in"
        except json.JSONDecodeError:
            return "logged-in"
    return None


def extract_appstore(bundle_id: str, out_dir: str, *, apple_id: Optional[str] = None) -> str:
    """Download an IPA from the App Store with ipatool (FairPlay-encrypted)."""
    ipatool = utils.require(
        "ipatool",
        "install it: brew install ipatool",
    )
    account = _ipatool_account()
    if not account:
        who = apple_id or "<your-apple-id>"
        raise IphError(
            "ipatool is not signed in. Log in first (handles 2FA interactively):\n"
            f"    ipatool auth login -e {who}"
        )
    utils.info(f"App Store account: {account}")

    import os
    os.makedirs(out_dir, exist_ok=True)
    utils.step(f"Downloading {bundle_id} from the App Store")
    cmd = [ipatool, "download", "-b", bundle_id, "-o", out_dir,
           "--purchase", "--format", "json"]
    proc = utils.run(cmd, check=False, capture=True)
    out = (proc.stdout or "") + "\n" + (proc.stderr or "")

    if proc.returncode != 0:
        low = out.lower()
        if "license" in low or "purchase" in low:
            raise IphError(
                f"could not obtain a license for {bundle_id}. The app must be free "
                "or already associated with this Apple ID.\n" + out.strip()
            )
        if "auth" in low or "login" in low or "keyring" in low:
            raise IphError("ipatool authentication problem.\n" + out.strip())
        raise IphError("App Store download failed.\n" + out.strip())

    # ipatool --format json prints a line like {"output":"/path/App.ipa",...}
    path = None
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                path = json.loads(line).get("output")
            except json.JSONDecodeError:
                pass
    utils.ok("downloaded — note: App Store IPAs are FairPlay-encrypted")
    if path:
        utils.ok(f"saved: {path}")
        return path
    return out_dir

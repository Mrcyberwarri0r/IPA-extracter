"""Install an IPA onto a device.

Installation is identical for jailbroken and non-jailbroken devices: the IPA
must carry a signature the device will accept (App Store, developer, ad-hoc, or
enterprise). This module does not sign — it installs an already-signed IPA and
surfaces a clear error if the signature is missing or rejected.

Two backends, tried in order: pymobiledevice3 (modern, iOS 17+), then
ideviceinstaller (libimobiledevice).
"""

from __future__ import annotations

import plistlib
import zipfile
from typing import Optional

from . import utils
from .device import Device
from .utils import IphError


def _inspect_ipa(ipa_path: str) -> dict:
    """Pull a few sanity facts out of the IPA before shipping it."""
    facts = {"bundle_id": None, "signed": False, "name": None}
    try:
        with zipfile.ZipFile(ipa_path) as zf:
            names = zf.namelist()
            info_name = next(
                (n for n in names
                 if n.startswith("Payload/") and n.endswith(".app/Info.plist")
                 and n.count("/") == 2),
                None,
            )
            if info_name:
                with zf.open(info_name) as fh:
                    plist = plistlib.load(fh)
                facts["bundle_id"] = plist.get("CFBundleIdentifier")
                facts["name"] = plist.get("CFBundleName") or plist.get("CFBundleDisplayName")
            app_dir = info_name.rsplit("/", 1)[0] if info_name else None
            if app_dir:
                facts["signed"] = f"{app_dir}/embedded.mobileprovision" in names or any(
                    n.startswith(f"{app_dir}/_CodeSignature/") for n in names
                )
    except (zipfile.BadZipFile, OSError) as e:
        raise IphError(f"not a readable IPA: {ipa_path} ({e})")
    return facts


def install(ipa_path: str, dev: Device, *, upgrade: bool = False) -> None:
    import os

    if not os.path.isfile(ipa_path):
        raise IphError(f"file not found: {ipa_path}")

    facts = _inspect_ipa(ipa_path)
    if facts["bundle_id"]:
        utils.info(f"IPA: {facts['name'] or '?'}  ({facts['bundle_id']})")
    if not facts["signed"]:
        utils.warn(
            "IPA has no embedded provisioning profile / code signature. "
            "Install will likely be rejected unless the device trusts this "
            "signature. Sign it first (e.g. with a developer cert / zsign)."
        )

    verb = "Upgrading" if upgrade else "Installing"
    utils.step(f"{verb} on {dev.name}")

    errors = []

    # Backend 1: pymobiledevice3
    pmd3 = utils.which("pymobiledevice3")
    if pmd3:
        cmd = [pmd3, "apps", "install", ipa_path, "--udid", dev.udid]
        proc = utils.run(cmd, check=False, capture=True)
        if proc.returncode == 0:
            utils.ok("installed via pymobiledevice3")
            return
        errors.append("pymobiledevice3: " + (proc.stderr or proc.stdout or "").strip())

    # Backend 2: ideviceinstaller
    idev = utils.which("ideviceinstaller")
    if idev:
        # v1.1+ uses subcommands: `install PATH` / `upgrade PATH`.
        verb_cmd = "upgrade" if upgrade else "install"
        cmd = [idev, "-u", dev.udid, verb_cmd, ipa_path]
        proc = utils.run(cmd, check=False, capture=True)
        out = (proc.stdout or "") + (proc.stderr or "")
        if proc.returncode == 0 and ("Complete" in out or "Install: Complete" in out):
            utils.ok("installed via ideviceinstaller")
            return
        errors.append("ideviceinstaller: " + out.strip())

    if not pmd3 and not idev:
        raise IphError(
            "no install backend found. Install either pymobiledevice3 or "
            "ideviceinstaller (brew install ideviceinstaller)."
        )

    raise IphError("installation failed.\n" + "\n".join(f"  - {e}" for e in errors if e))

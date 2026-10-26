"""Device discovery and information.

Uses pymobiledevice3 (preferred, works through iOS 17+) with a libimobiledevice
fallback, so the tool keeps working whichever stack is healthier on a given box.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import List, Optional

from . import utils
from .utils import IphError


@dataclass
class Device:
    udid: str
    name: str = "?"
    product_type: str = "?"
    ios_version: str = "?"
    connection: str = "usb"  # usb | network

    def label(self) -> str:
        return f"{self.name} ({self.product_type}, iOS {self.ios_version}) [{self.udid[:12]}…]"


def _pmd3() -> Optional[str]:
    return utils.which("pymobiledevice3")


def list_devices() -> List[Device]:
    """Return all attached devices (USB + network) deduplicated by UDID."""
    devices: dict[str, Device] = {}

    # Preferred: pymobiledevice3 usbmux list --usbmux-address? just `usbmux list`
    pmd3 = _pmd3()
    if pmd3:
        try:
            proc = utils.run([pmd3, "usbmux", "list"], capture=True, check=False)
            raw = (proc.stdout or "").strip()
            if raw:
                data = json.loads(raw)
                for entry in data:
                    udid = entry.get("Identifier") or entry.get("UniqueDeviceID")
                    if not udid:
                        continue
                    conn = (entry.get("ConnectionType") or "usb").lower()
                    dev = devices.get(udid) or Device(udid=udid)
                    dev.name = entry.get("DeviceName", dev.name)
                    dev.product_type = entry.get("ProductType", dev.product_type)
                    dev.ios_version = entry.get("ProductVersion", dev.ios_version)
                    dev.connection = "network" if "network" in conn else "usb"
                    devices[udid] = dev
        except (json.JSONDecodeError, IphError):
            pass

    # Fallback: libimobiledevice
    if not devices and utils.which("idevice_id"):
        proc = utils.run(["idevice_id", "-l"], capture=True, check=False)
        for udid in (proc.stdout or "").split():
            udid = udid.strip()
            if udid:
                devices[udid] = _enrich_libimobile(Device(udid=udid))

    return list(devices.values())


def _enrich_libimobile(dev: Device) -> Device:
    if not utils.which("ideviceinfo"):
        return dev
    keys = {
        "DeviceName": "name",
        "ProductType": "product_type",
        "ProductVersion": "ios_version",
    }
    for plist_key, attr in keys.items():
        proc = utils.run(
            ["ideviceinfo", "-u", dev.udid, "-k", plist_key],
            capture=True,
            check=False,
        )
        val = (proc.stdout or "").strip()
        if val:
            setattr(dev, attr, val)
    return dev


def resolve(udid: Optional[str]) -> Device:
    """Pick the target device. Errors clearly on none / ambiguous."""
    devices = list_devices()
    if not devices:
        raise IphError(
            "no iOS device detected. Connect via USB and trust the computer "
            "(unlock device → tap 'Trust'). For Wi-Fi, pair first with "
            "`pymobiledevice3 lockdown pair`."
        )
    if udid:
        for d in devices:
            if d.udid == udid or d.udid.startswith(udid):
                return d
        raise IphError(f"device '{udid}' not found. Attached: " + ", ".join(d.udid for d in devices))
    if len(devices) == 1:
        return devices[0]
    listing = "\n".join(f"    {d.udid}  {d.label()}" for d in devices)
    raise IphError(f"multiple devices attached; choose one with --udid:\n{listing}")


def ensure_developer_image(udid: str) -> bool:
    """Mount the Developer Disk Image if absent (iOS 17+ needs it for Frida
    spawn/attach on non-jailbroken devices). Returns True if an image is mounted.

    Harmless on jailbroken devices running frida-server (they don't need it).
    """
    pmd3 = _pmd3()
    if not pmd3:
        return False
    # Already mounted?
    proc = utils.run([pmd3, "mounter", "list", "--udid", udid], capture=True, check=False)
    out = (proc.stdout or "").strip()
    if out and out != "[]":
        return True
    utils.info("mounting Developer Disk Image (needed for Frida on non-jailbroken iOS 17+)…")
    proc = utils.run([pmd3, "mounter", "auto-mount", "--udid", udid], capture=True, check=False)
    err = (proc.stderr or "") + (proc.stdout or "")
    if "DeviceLocked" in err:
        raise IphError("device is locked — unlock the iPhone and keep it on, then retry.")
    if "Developer Mode" in err or "developer mode" in err:
        raise IphError(
            "enable Developer Mode on the device: Settings → Privacy & Security → "
            "Developer Mode → on, then reboot and retry."
        )
    if proc.returncode != 0 and "already" not in err.lower():
        utils.warn("DDI auto-mount reported: " + err.strip().splitlines()[-1] if err.strip() else "unknown")
    # Re-check.
    proc = utils.run([pmd3, "mounter", "list", "--udid", udid], capture=True, check=False)
    out = (proc.stdout or "").strip()
    return bool(out) and out != "[]"


def is_developer_mode_required(dev: Device) -> bool:
    """iOS 16+ gates many operations behind Developer Mode."""
    try:
        major = int(dev.ios_version.split(".")[0])
    except (ValueError, IndexError):
        return False
    return major >= 16

"""Drive the Frida agent to produce a decrypted .ipa.

Works against any device Frida can reach: a jailbroken device running
frida-server, or an app repackaged with the Frida gadget. The driver spawns
(or attaches to) the target, lets its binaries decrypt in memory, then pulls
the bundle file-by-file, swapping in decrypted Mach-Os as it goes.
"""

from __future__ import annotations

import os
import posixpath
import shutil
import sys
import time
import zipfile
from pathlib import Path
from typing import Optional

from . import utils
from .utils import IphError

_AGENT = Path(__file__).with_name("scripts") / "dump.js"


def _load_frida():
    try:
        import frida  # noqa
        return frida
    except ImportError as e:  # pragma: no cover
        raise IphError(
            "the 'frida' Python module is required for extraction. "
            "Install it in this tool's environment (pip install frida)."
        ) from e


def _get_device(frida, udid: Optional[str], timeout: float = 10.0):
    if udid:
        return frida.get_device(udid, timeout=timeout)
    return frida.get_usb_device(timeout=timeout)


def _find_app(device, target: str):
    """Match `target` against bundle id, then name (case-insensitive)."""
    apps = device.enumerate_applications()
    for a in apps:
        if a.identifier == target:
            return a
    low = target.lower()
    for a in apps:
        if a.identifier.lower() == low or (a.name or "").lower() == low:
            return a
    for a in apps:
        if low in a.identifier.lower() or low in (a.name or "").lower():
            return a
    raise IphError(
        f"app '{target}' not found on device. List installed apps with: iph apps"
    )


def _needs_ddi(exc: Exception) -> bool:
    return "Developer Disk Image" in str(exc) or "DeveloperDiskImage" in str(exc)


def _open_session(frida, device, app, attach: bool, udid):
    from . import device as device_mod

    pid = None
    spawned = False
    if not attach:
        try:
            pid = device.spawn([app.identifier])
            spawned = True
        except Exception as e:  # frida.NotSupportedError etc.
            if _needs_ddi(e):
                device_mod.ensure_developer_image(udid or device.id)
                pid = device.spawn([app.identifier])
                spawned = True
            else:
                utils.warn(f"spawn failed ({e}); trying to attach to a running instance.")
    if pid is None:
        if app.pid:
            pid = app.pid
        else:
            raise IphError(
                f"could not spawn '{app.identifier}' and it is not running. "
                "Open the app manually and retry with --attach."
            )
    try:
        session = device.attach(pid)
    except Exception as e:
        if _needs_ddi(e):
            device_mod_attach(udid or device.id)
            session = device.attach(pid)
        elif _is_not_debuggable(e):
            # Clean up the suspended spawn we can't instrument.
            if spawned:
                _safe_kill(device, pid)
            raise IphError(
                f"cannot instrument '{app.identifier}' on this device.\n"
                "Frida could launch it but not attach — the app is not debuggable "
                "(no 'get-task-allow' entitlement). On a NON-jailbroken device that "
                "is normal for App Store apps, so they cannot be decrypted here.\n"
                "Options:\n"
                "  • Decrypt it on a JAILBROKEN device (frida-server as root).\n"
                "  • This path works on non-jailbroken devices only for apps YOU "
                "signed (development / ad-hoc / sideloaded).\n"
                "  • To just archive the App Store IPA (still encrypted), use:\n"
                f"        iph extract {app.identifier} --method appstore"
            ) from e
        else:
            if spawned:
                _safe_kill(device, pid)
            raise
    return session, pid, spawned


def _is_not_debuggable(exc: Exception) -> bool:
    msg = str(exc).lower()
    return (
        "unable to attach to the specified process" in msg
        or "process is not debuggable" in msg
        or "not permitted" in msg
    )


def _safe_kill(device, pid) -> None:
    try:
        device.kill(pid)
    except Exception:
        pass


def device_mod_attach(udid):
    from . import device as device_mod
    device_mod.ensure_developer_image(udid)


def dump(
    target: str,
    out_path: str,
    *,
    udid: Optional[str] = None,
    attach: bool = False,
) -> str:
    frida = _load_frida()
    device = _get_device(frida, udid)
    app = _find_app(device, target)
    utils.info(f"target: {app.name}  ({app.identifier})")

    session, pid, spawned = _open_session(frida, device, app, attach, udid)

    script_src = _AGENT.read_text()
    script = session.create_script(script_src)
    errors: list[str] = []
    script.on("message", lambda m, d: errors.append(str(m)) if m.get("type") == "error" else None)
    script.load()

    if spawned:
        device.resume(pid)
        time.sleep(1.0)  # let frameworks map + decrypt

    api = script.exports_sync

    utils.step("Enumerating app bundle")
    meta = api.enumerate()
    bundle_name = meta["bundleName"]
    app_path = meta["appPath"]
    files = meta["files"]
    encrypted = set(api.encrypted_modules())
    utils.info(f"bundle: {bundle_name}  files: {len(files)}  encrypted Mach-Os: {len(encrypted)}")
    if not encrypted:
        utils.warn("no encrypted Mach-Os detected — binary may already be decrypted "
                    "or linked frameworks were not loaded. Proceeding anyway.")

    # Stage locally: <stage>/Payload/<Bundle>.app/...
    stage = Path(out_path + ".stage")
    if stage.exists():
        shutil.rmtree(stage)
    app_root = stage / "Payload" / bundle_name
    app_root.mkdir(parents=True, exist_ok=True)

    total = len([f for f in files if not f["dir"]])
    done = 0
    for f in files:
        rel = f["path"]
        dest = app_root / rel
        if f["dir"]:
            dest.mkdir(parents=True, exist_ok=True)
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        abs_remote = posixpath.join(app_path, rel)
        try:
            if abs_remote in encrypted:
                data = api.decrypt_module(abs_remote)
            else:
                data = api.read_file(abs_remote)
        except Exception as e:
            utils.warn(f"skip {rel}: {e}")
            data = None
        if data is not None:
            with open(dest, "wb") as fh:
                fh.write(data)
        done += 1
        _progress(done, total, rel)
    sys.stderr.write("\n")

    try:
        script.unload()
    except Exception:
        pass
    try:
        session.detach()
    except Exception:
        pass

    utils.step("Packaging .ipa")
    ipa = _zip_payload(stage, out_path)
    shutil.rmtree(stage, ignore_errors=True)
    size = os.path.getsize(ipa)
    utils.ok(f"wrote {ipa}  ({utils.human_size(size)})")
    return ipa


def _progress(done: int, total: int, name: str) -> None:
    pct = (done / total * 100) if total else 100
    name = (name[:40] + "…") if len(name) > 41 else name
    sys.stderr.write(f"\r    [{done}/{total}] {pct:5.1f}%  {name:<42}")
    sys.stderr.flush()


def _zip_payload(stage: Path, out_path: str) -> str:
    out = Path(out_path)
    if out.suffix.lower() != ".ipa":
        out = out.with_suffix(".ipa")
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        out.unlink()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        payload = stage / "Payload"
        for root, _dirs, fnames in os.walk(payload):
            for fn in fnames:
                full = Path(root) / fn
                arc = os.path.join("Payload", os.path.relpath(full, payload))
                zf.write(full, arc)
    return str(out)

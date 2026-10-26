"""Offline unit tests — no device, no network. Run: python -m unittest -v"""

import os
import plistlib
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

from iph import cli, install
from iph.frida_dump import _zip_payload, _is_not_debuggable, _needs_ddi


def make_ipa(path, *, signed=True, bundle_id="com.test.app", name="App"):
    info = plistlib.dumps({
        "CFBundleIdentifier": bundle_id,
        "CFBundleName": name,
        "CFBundleExecutable": name,
    })
    with zipfile.ZipFile(path, "w") as z:
        app = f"Payload/{name}.app"
        z.writestr(f"{app}/Info.plist", info)
        z.writestr(f"{app}/{name}", b"\xcf\xfa\xed\xfe binary")
        if signed:
            z.writestr(f"{app}/_CodeSignature/CodeResources", "<xml/>")
            z.writestr(f"{app}/embedded.mobileprovision", b"profile")


class TestIpaInspector(unittest.TestCase):
    def test_signed(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "a.ipa")
            make_ipa(p, signed=True)
            facts = install._inspect_ipa(p)
            self.assertEqual(facts["bundle_id"], "com.test.app")
            self.assertEqual(facts["name"], "App")
            self.assertTrue(facts["signed"])

    def test_unsigned(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "a.ipa")
            make_ipa(p, signed=False)
            self.assertFalse(install._inspect_ipa(p)["signed"])

    def test_not_an_ipa(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "bad.ipa")
            Path(p).write_bytes(b"not a zip")
            with self.assertRaises(Exception):
                install._inspect_ipa(p)


class TestPackaging(unittest.TestCase):
    def test_zip_payload_structure(self):
        with tempfile.TemporaryDirectory() as d:
            stage = Path(d) / "s.stage"
            app = stage / "Payload" / "Demo.app"
            (app / "Frameworks" / "L.framework").mkdir(parents=True)
            (app / "Demo").write_bytes(b"\xcf\xfa\xed\xfe main")
            (app / "Info.plist").write_bytes(b"<plist/>")
            (app / "Frameworks" / "L.framework" / "L").write_bytes(b"lib")
            out = _zip_payload(stage, str(Path(d) / "out.ipa"))
            with zipfile.ZipFile(out) as z:
                self.assertIsNone(z.testzip())
                names = z.namelist()
            self.assertIn("Payload/Demo.app/Demo", names)
            self.assertIn("Payload/Demo.app/Frameworks/L.framework/L", names)
            self.assertTrue(all(not n.startswith("/") for n in names))


class TestMachOContract(unittest.TestCase):
    """Reference mirror of dump.js parseEncryption(): guards the byte offsets
    the agent relies on so a regression here flags a mismatch with dump.js."""

    MH_MAGIC_64 = 0xfeedfacf
    LC_ENCRYPTION_INFO_64 = 0x2c

    def parse(self, buf):
        magic = struct.unpack_from("<I", buf, 0)[0]
        is64 = magic in (self.MH_MAGIC_64, 0xcffaedfe)
        ncmds = struct.unpack_from("<I", buf, 16)[0]
        off = 32 if is64 else 28
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", buf, off)
            if cmd == self.LC_ENCRYPTION_INFO_64:
                co, cs, cid = struct.unpack_from("<III", buf, off + 8)
                return dict(found=True, cryptoff=co, cryptsize=cs,
                            cryptid=cid, cryptidFileOff=off + 16)
            off += cmdsize
        return dict(found=False)

    def test_finds_and_patches(self):
        hdr = struct.pack("<IiiIIIII", self.MH_MAGIC_64, 0x0100000c, 0, 2, 2, 0, 0, 0)
        lc1 = struct.pack("<II", 0x19, 72) + b"\x00" * 64           # LC_SEGMENT_64
        lc2 = struct.pack("<IIIIII", self.LC_ENCRYPTION_INFO_64, 24, 16384, 32768, 1, 0)
        buf = hdr + lc1 + lc2
        r = self.parse(buf)
        self.assertTrue(r["found"])
        self.assertEqual((r["cryptoff"], r["cryptsize"], r["cryptid"]), (16384, 32768, 1))
        self.assertEqual(struct.unpack_from("<I", buf, r["cryptidFileOff"])[0], 1)
        b = bytearray(buf)
        struct.pack_into("<I", b, r["cryptidFileOff"], 0)
        self.assertEqual(self.parse(bytes(b))["cryptid"], 0)

    def test_overlay_and_clear_mechanics(self):
        """Matches dump.js decryptModule's buffer ops: overlay the decrypted
        pages over the encrypted region and clear cryptid without touching
        anything else. In a real FairPlay binary the cryptid field sits before
        cryptoff, so clearing it changes a byte ahead of the region, which is
        expected."""
        # Build a header whose cryptid field precedes the encrypted region.
        cryptoff, cryptsize = 16384, 4096
        hdr = struct.pack("<IiiIIIII", self.MH_MAGIC_64, 0x0100000c, 0, 2, 1, 0, 0, 0)
        enc = struct.pack("<IIIIII", self.LC_ENCRYPTION_INFO_64, 24, cryptoff, cryptsize, 1, 0)
        head = hdr + enc
        raw = head + b"\xAA" * (cryptoff - len(head)) + b"\xEE" * cryptsize + b"\xBB" * 256
        r = self.parse(raw)
        self.assertEqual((r["cryptoff"], r["cryptsize"], r["cryptid"]), (cryptoff, cryptsize, 1))
        cidoff = r["cryptidFileOff"]
        self.assertLess(cidoff, cryptoff)

        decrypted = bytes((i * 7 + 3) & 0xFF for i in range(cryptsize))
        out = bytearray(raw)
        out[cryptoff:cryptoff + cryptsize] = decrypted        # Uint8Array.set(...)
        struct.pack_into("<I", out, cidoff, 0)                # DataView.setUint32(...,0)
        out = bytes(out)

        self.assertEqual(out[cryptoff:cryptoff + cryptsize], decrypted)
        self.assertEqual(self.parse(out)["cryptid"], 0)
        self.assertEqual(len(out), len(raw))
        self.assertEqual(out[:cidoff], raw[:cidoff])
        self.assertEqual(out[cidoff + 4:cryptoff], raw[cidoff + 4:cryptoff])
        self.assertEqual(out[cryptoff + cryptsize:], raw[cryptoff + cryptsize:])


class TestCliParser(unittest.TestCase):
    def test_subcommands(self):
        p = cli.build_parser()
        for args in (["devices"], ["apps", "--all"], ["install", "x.ipa"],
                     ["extract", "com.x", "--method", "appstore"], ["doctor"]):
            ns = p.parse_args(args)
            self.assertTrue(ns.command)

    def test_error_classifiers(self):
        self.assertTrue(_is_not_debuggable(Exception("unable to attach to the specified process")))
        self.assertTrue(_needs_ddi(Exception("requires an iOS Developer Disk Image to be mounted")))
        self.assertFalse(_is_not_debuggable(Exception("some other error")))


if __name__ == "__main__":
    unittest.main()

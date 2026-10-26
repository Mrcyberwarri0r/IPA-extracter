/*
 * iph Frida agent — in-memory decryption of an iOS app bundle.
 *
 * App Store binaries ship with an encrypted __TEXT region (FairPlay). Once the
 * loader maps and runs them, the pages are decrypted in RAM. This agent reads
 * those decrypted pages back, rewrites the Mach-O's LC_ENCRYPTION_INFO so
 * cryptid=0, and hands the clean file back to the Python driver.
 *
 * Exports:
 *   enumerate()            -> metadata + file list + which Mach-Os are encrypted
 *   readFile(absPath)      -> ArrayBuffer of a file as-is on disk
 *   decryptModule(absPath) -> ArrayBuffer of that Mach-O, decrypted + patched
 */

'use strict';

const MH_MAGIC_64 = 0xfeedfacf;
const MH_CIGAM_64 = 0xcffaedfe;
const MH_MAGIC_32 = 0xfeedface;
const LC_ENCRYPTION_INFO = 0x21;
const LC_ENCRYPTION_INFO_64 = 0x2c;

function nsstr(s) {
  return ObjC.classes.NSString.stringWithUTF8String_(Memory.allocUtf8String(s));
}

function mainBundle() {
  return ObjC.classes.NSBundle.mainBundle();
}

function appPath() {
  return mainBundle().bundlePath().toString();
}

function dataPath() {
  // The app's Documents dir sits inside the data container.
  // 9 = NSDocumentDirectory, 1 = NSUserDomainMask
  const arr = ObjC.classes.NSFileManager.defaultManager()
    .URLsForDirectory_inDomains_(9, 1);
  if (arr.count().valueOf() > 0) {
    return arr.objectAtIndex_(0).path().toString();
  }
  return '';
}

// Recursively list everything under `root`, returning paths relative to it.
function listFiles(root) {
  const fm = ObjC.classes.NSFileManager.defaultManager();
  const out = [];
  const en = fm.enumeratorAtPath_(nsstr(root));
  let rel;
  while ((rel = en.nextObject()) !== null) {
    const relStr = rel.toString();
    const abs = root + '/' + relStr;
    const isDirPtr = Memory.alloc(Process.pointerSize);
    fm.fileExistsAtPath_isDirectory_(nsstr(abs), isDirPtr);
    const isDir = isDirPtr.readU8() !== 0;
    let size = 0;
    if (!isDir) {
      const attrs = fm.attributesOfItemAtPath_error_(nsstr(abs), NULL);
      if (attrs !== null) {
        const n = attrs.objectForKey_(nsstr('NSFileSize'));
        if (n !== null) size = n.unsignedLongLongValue().valueOf();
      }
    }
    out.push({ path: relStr, size: size, dir: isDir });
  }
  return out;
}

// Map loaded Mach-O modules that live inside the app bundle, keyed by abs path.
function loadedBundleModules() {
  const base = appPath();
  const map = {};
  for (const m of Process.enumerateModules()) {
    if (m.path.indexOf(base) === 0) {
      map[m.path] = m.base;
    }
  }
  return map;
}

// Inspect an on-disk Mach-O header to find its encryption command.
// Returns {found, is64, cryptoff, cryptsize, cryptid, cmdCryptidAddrOffset}.
function parseEncryption(buf) {
  const u32 = (off) => buf.add(off).readU32();
  const magic = u32(0);
  let is64;
  if (magic === MH_MAGIC_64 || magic === MH_CIGAM_64) is64 = true;
  else if (magic === MH_MAGIC_32) is64 = false;
  else return { found: false, fat: magic === 0xcafebabe || magic === 0xbebafeca };

  const ncmds = u32(16);
  let off = is64 ? 32 : 28;
  for (let i = 0; i < ncmds; i++) {
    const cmd = u32(off);
    const cmdsize = u32(off + 4);
    if (cmd === LC_ENCRYPTION_INFO || cmd === LC_ENCRYPTION_INFO_64) {
      const cryptoff = u32(off + 8);
      const cryptsize = u32(off + 12);
      const cryptid = u32(off + 16);
      return {
        found: true, is64, cryptoff, cryptsize, cryptid,
        cryptidFileOff: off + 16,
      };
    }
    off += cmdsize;
  }
  return { found: false, is64 };
}

function readWholeFile(absPath) {
  const data = ObjC.classes.NSData.dataWithContentsOfFile_(nsstr(absPath));
  if (data === null) {
    throw new Error('cannot read file: ' + absPath);
  }
  const len = data.length().valueOf();
  const bytes = data.bytes();
  return { ptr: bytes, len: len };
}

rpc.exports = {
  enumerate: function () {
    const ap = appPath();
    const loaded = loadedBundleModules();
    const encrypted = [];
    for (const p in loaded) {
      try {
        const f = readWholeFile(p);
        const enc = parseEncryption(f.ptr);
        if (enc.found && enc.cryptid !== 0) {
          encrypted.push(p);
        }
      } catch (e) { /* skip unreadable */ }
    }
    return {
      bundleId: mainBundle().bundleIdentifier().toString(),
      bundleName: ap.split('/').pop(),
      appPath: ap,
      dataPath: dataPath(),
      files: listFiles(ap),
      encrypted: encrypted,
    };
  },

  // Return a file verbatim as an ArrayBuffer.
  readFile: function (absPath) {
    const f = readWholeFile(absPath);
    return f.ptr.readByteArray(f.len);
  },

  // Return a decrypted + cryptid-cleared copy of a loaded Mach-O.
  decryptModule: function (absPath) {
    const loaded = loadedBundleModules();
    const base = loaded[absPath];
    if (!base) throw new Error('module not loaded: ' + absPath);

    const f = readWholeFile(absPath);
    const enc = parseEncryption(f.ptr);
    if (enc.fat) {
      throw new Error('fat/universal binary not supported by in-memory dump: ' + absPath);
    }
    if (!enc.found || enc.cryptid === 0) {
      // Nothing to do — hand back the original bytes.
      return f.ptr.readByteArray(f.len);
    }

    // Copy the whole file into a writable buffer we can patch.
    const out = Memory.alloc(f.len);
    Memory.copy(out, f.ptr, f.len);

    // Overwrite the encrypted region with the decrypted in-memory pages.
    const decrypted = base.add(enc.cryptoff).readByteArray(enc.cryptsize);
    out.add(enc.cryptoff).writeByteArray(decrypted);

    // Clear cryptid so the tooling treats it as decrypted.
    out.add(enc.cryptidFileOff).writeU32(0);

    return out.readByteArray(f.len);
  },
};

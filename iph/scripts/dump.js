/*
 * iph Frida agent — in-memory decryption of an iOS app bundle.
 *
 * App Store binaries ship with an encrypted __TEXT region (FairPlay, cryptid=1).
 * Once the loader maps and runs them, those pages are decrypted in RAM. This
 * agent reads the decrypted pages back, rewrites the Mach-O's
 * LC_ENCRYPTION_INFO(_64) so cryptid=0, and hands the clean file to the driver.
 *
 * Bridge-free by design: it uses only core Frida APIs (Process, Module, Memory,
 * File) plus libc via NativeFunction — no frida-objc-bridge — so it runs on
 * Frida 16 and 17+ alike, loaded as a plain script with no compile step.
 *
 * Exports:
 *   enumerate()            -> { appPath, bundleName, files: [{path, dir}] }
 *   readFile(absPath)      -> ArrayBuffer of a file as-is on disk
 *   decryptModule(absPath) -> ArrayBuffer of that Mach-O, decrypted + patched
 */

'use strict';

const MH_MAGIC_64 = 0xfeedfacf;
const MH_CIGAM_64 = 0xcffaedfe;
const MH_MAGIC_32 = 0xfeedface;
const MH_CIGAM_32 = 0xcefaedfe;
const FAT_MAGIC = 0xcafebabe;
const FAT_CIGAM = 0xbebafeca;
const LC_ENCRYPTION_INFO = 0x21;
const LC_ENCRYPTION_INFO_64 = 0x2c;

// Directory entry type (Darwin <dirent.h>).
const DT_DIR = 4;

// ---------------------------------------------------------------------------
// Symbol resolution that works across Frida versions.
// ---------------------------------------------------------------------------
function globalExport(name) {
  if (typeof Module.getGlobalExportByName === 'function') {
    return Module.getGlobalExportByName(name);
  }
  // Older Frida.
  return Module.findExportByName(null, name);
}

const _opendir = new NativeFunction(globalExport('opendir'), 'pointer', ['pointer']);
const _readdir = new NativeFunction(globalExport('readdir'), 'pointer', ['pointer']);
const _closedir = new NativeFunction(globalExport('closedir'), 'int', ['pointer']);

// ---------------------------------------------------------------------------
// Path + bundle helpers.
// ---------------------------------------------------------------------------
function mainExecutablePath() {
  // Process.mainModule is available on Frida 16+.
  if (Process.mainModule && Process.mainModule.path) {
    return Process.mainModule.path;
  }
  // Fallback: first enumerated module is the main image.
  return Process.enumerateModules()[0].path;
}

function dirname(p) {
  const i = p.lastIndexOf('/');
  return i <= 0 ? '/' : p.substring(0, i);
}

function basename(p) {
  const i = p.lastIndexOf('/');
  return i < 0 ? p : p.substring(i + 1);
}

function appBundlePath() {
  // For an iOS app the main executable sits directly inside Foo.app/.
  return dirname(mainExecutablePath());
}

// Recursively list everything under `root`, as paths relative to it.
// Uses libc opendir/readdir so no Objective-C bridge is required.
function listFiles(root) {
  const out = [];
  walk(root, '', out);
  return out;
}

function walk(absDir, relPrefix, out) {
  const dp = _opendir(Memory.allocUtf8String(absDir));
  if (dp.isNull()) return;
  try {
    let ent;
    while (!(ent = _readdir(dp)).isNull()) {
      // struct dirent (Darwin, 64-bit inode):
      //   d_ino(8) d_seekoff(8) d_reclen(2) d_namlen(2) d_type(1) d_name[]
      const namlen = ent.add(18).readU16();
      const type = ent.add(20).readU8();
      const name = ent.add(21).readUtf8String(namlen);
      if (name === '.' || name === '..') continue;
      const rel = relPrefix ? relPrefix + '/' + name : name;
      const isDir = type === DT_DIR;
      out.push({ path: rel, dir: isDir });
      if (isDir) {
        walk(absDir + '/' + name, rel, out);
      }
    }
  } finally {
    _closedir(dp);
  }
}

function readFileBytes(absPath) {
  // File.readAllBytes returns an ArrayBuffer (Frida 16+).
  return File.readAllBytes(absPath);
}

// ---------------------------------------------------------------------------
// Mach-O inspection (operates on an ArrayBuffer via DataView, little-endian
// since every device slice we care about is little-endian ARM).
// ---------------------------------------------------------------------------
function parseEncryption(buf) {
  const dv = new DataView(buf);
  const magic = dv.getUint32(0, true);
  if (magic === FAT_MAGIC || magic === FAT_CIGAM) {
    return { found: false, fat: true };
  }
  let is64;
  if (magic === MH_MAGIC_64 || magic === MH_CIGAM_64) is64 = true;
  else if (magic === MH_MAGIC_32 || magic === MH_CIGAM_32) is64 = false;
  else return { found: false, notMacho: true };

  const ncmds = dv.getUint32(16, true);
  let off = is64 ? 32 : 28;
  for (let i = 0; i < ncmds; i++) {
    const cmd = dv.getUint32(off, true);
    const cmdsize = dv.getUint32(off + 4, true);
    if (cmd === LC_ENCRYPTION_INFO || cmd === LC_ENCRYPTION_INFO_64) {
      return {
        found: true,
        is64,
        cryptoff: dv.getUint32(off + 8, true),
        cryptsize: dv.getUint32(off + 12, true),
        cryptid: dv.getUint32(off + 16, true),
        cryptidFileOff: off + 16,
      };
    }
    if (cmdsize === 0) break; // malformed; avoid infinite loop
    off += cmdsize;
  }
  return { found: false, is64 };
}

// Map loaded Mach-O modules that live inside the app bundle: absPath -> base.
function loadedBundleModules() {
  const base = appBundlePath();
  const map = {};
  for (const m of Process.enumerateModules()) {
    if (m.path.indexOf(base) === 0) map[m.path] = m.base;
  }
  return map;
}

// ---------------------------------------------------------------------------
// RPC surface.
// ---------------------------------------------------------------------------
rpc.exports = {
  enumerate: function () {
    const ap = appBundlePath();
    return {
      appPath: ap,
      bundleName: basename(ap),
      files: listFiles(ap),
    };
  },

  // Which of the bundle's loaded Mach-Os are still encrypted.
  encryptedModules: function () {
    const loaded = loadedBundleModules();
    const encrypted = [];
    for (const p in loaded) {
      try {
        const enc = parseEncryption(readFileBytes(p));
        if (enc.found && enc.cryptid !== 0) encrypted.push(p);
      } catch (e) { /* unreadable / not a mach-o — skip */ }
    }
    return encrypted;
  },

  // Return a file verbatim as an ArrayBuffer.
  readFile: function (absPath) {
    return readFileBytes(absPath);
  },

  // Return a decrypted + cryptid-cleared copy of a loaded Mach-O.
  decryptModule: function (absPath) {
    const loaded = loadedBundleModules();
    const base = loaded[absPath];
    if (!base) throw new Error('module not loaded: ' + absPath);

    const buf = readFileBytes(absPath);
    const enc = parseEncryption(buf);
    if (enc.fat) {
      throw new Error('fat/universal binary not supported by in-memory dump: ' + absPath);
    }
    if (!enc.found || enc.cryptid === 0) {
      return buf; // already decrypted — hand back as-is
    }

    // Overwrite the encrypted region with the decrypted in-memory pages.
    const decrypted = base.add(enc.cryptoff).readByteArray(enc.cryptsize);
    const fileU8 = new Uint8Array(buf);
    fileU8.set(new Uint8Array(decrypted), enc.cryptoff);

    // Clear cryptid so downstream tooling treats it as decrypted.
    new DataView(buf).setUint32(enc.cryptidFileOff, 0, true);
    return buf;
  },
};

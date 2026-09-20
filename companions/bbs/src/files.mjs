import fs from 'node:fs';
import path from 'node:path';
import {requireThat} from './encoding.mjs';

function metadata(s, secret) {
  requireThat(s.isFile() && s.nlink === 1);
  if(process.platform !== 'win32' && secret) {
    requireThat((s.mode & 0o777) === 0o600 && s.uid === process.getuid());
  }
}
export function privateParent(file) {
  let current = path.dirname(path.resolve(file));
  while(true) {
    requireThat(!fs.lstatSync(current).isSymbolicLink());
    const next = path.dirname(current);
    if(next === current) break;
    current = next;
  }
  const parent = fs.lstatSync(path.dirname(path.resolve(file)));
  requireThat(parent.isDirectory() && !parent.isSymbolicLink());
  if(process.platform !== 'win32') {
    requireThat((parent.mode & 0o022) === 0 && parent.uid === process.getuid());
  }
}
export function readRegular(file, limit, secret = true) {
  privateParent(file);
  const before = fs.lstatSync(file);
  metadata(before, secret);
  const fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const current = fs.fstatSync(fd);
    metadata(current, secret);
    requireThat(current.dev === before.dev && current.ino === before.ino &&
      current.size > 0 && current.size <= limit);
    const raw = Buffer.alloc(limit + 1);
    let used = 0, n;
    while(used < raw.length && (n = fs.readSync(fd, raw, used, raw.length - used, null))) {
      used += n;
    }
    requireThat(used > 0 && used <= limit);
    return raw.subarray(0, used);
  } finally { fs.closeSync(fd); }
}
export function writeExclusive(file, raw) {
  privateParent(file);
  const fd = fs.openSync(file, fs.constants.O_CREAT | fs.constants.O_EXCL |
    fs.constants.O_WRONLY | (fs.constants.O_NOFOLLOW || 0), 0o600);
  const own = fs.fstatSync(fd);
  try {
    fs.writeFileSync(fd, raw);
    fs.fsyncSync(fd);
  } catch(error) {
    try {
      const current = fs.lstatSync(file);
      if(current.dev === own.dev && current.ino === own.ino) fs.unlinkSync(file);
    } catch { /* Never delete an unrelated replacement file. */ }
    throw error;
  } finally { fs.closeSync(fd); }
}
export function passphrase(file) {
  const raw = readRegular(file, 1026);
  try {
    let end = raw.length;
    if(raw[end - 1] === 10) {
      end--;
      if(raw[end - 1] === 13) end--;
    }
    const value = raw.subarray(0, end);
    requireThat(value.length >= 16 && value.length <= 1024 &&
      !value.includes(0) && !value.includes(10) && !value.includes(13));
    new TextDecoder('utf-8', {fatal: true, ignoreBOM: true}).decode(value);
    requireThat(!(value[0] === 239 && value[1] === 187 && value[2] === 191));
    return Buffer.from(value);
  } finally { raw.fill(0); }
}
export function capability(file) {
  const raw = readRegular(file, 65);
  try {
    requireThat(/^[0-9a-f]{64}\n$/.test(raw.toString('latin1')));
    return Buffer.from(raw.subarray(0, 64));
  } finally { raw.fill(0); }
}

import { deflateRawSync } from 'node:zlib';

const CRC_TABLE = Array.from({ length: 256 }, (_, byte) => {
  let value = byte;
  for (let bit = 0; bit < 8; bit += 1) value = (value & 1) ? (0xedb88320 ^ (value >>> 1)) : (value >>> 1);
  return value >>> 0;
});

export function crc32(bytes) {
  let value = 0xffffffff;
  for (const byte of bytes) value = CRC_TABLE[(value ^ byte) & 0xff] ^ (value >>> 8);
  return (value ^ 0xffffffff) >>> 0;
}

function asBytes(value = '') {
  return Buffer.isBuffer(value) ? value : Buffer.from(value);
}

function zipEntry(entry, offset) {
  const name = asBytes(entry.name);
  const content = asBytes(entry.content);
  const method = entry.method ?? 0;
  const compressed = entry.compressed ?? (method === 8 ? deflateRawSync(content) : content);
  const flags = entry.flags ?? 0x800;
  const crc = entry.crc ?? crc32(content);
  const declaredCompressed = entry.compressedSize ?? compressed.length;
  const declaredSize = entry.size ?? content.length;
  const localName = asBytes(entry.localName ?? entry.name);
  const localFlags = entry.localFlags ?? flags;
  const localMethod = entry.localMethod ?? method;
  const localCrc = entry.localCrc ?? crc;
  const localCompressed = entry.localCompressedSize ?? declaredCompressed;
  const localSize = entry.localSize ?? declaredSize;

  const local = Buffer.alloc(30 + localName.length);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(20, 4);
  local.writeUInt16LE(localFlags, 6);
  local.writeUInt16LE(localMethod, 8);
  local.writeUInt32LE(localCrc >>> 0, 14);
  local.writeUInt32LE(localCompressed >>> 0, 18);
  local.writeUInt32LE(localSize >>> 0, 22);
  local.writeUInt16LE(localName.length, 26);
  local.writeUInt16LE(0, 28);
  localName.copy(local, 30);

  const central = Buffer.alloc(46 + name.length);
  central.writeUInt32LE(0x02014b50, 0);
  central.writeUInt16LE(entry.versionMadeBy ?? 0x031e, 4);
  central.writeUInt16LE(20, 6);
  central.writeUInt16LE(flags, 8);
  central.writeUInt16LE(method, 10);
  central.writeUInt32LE(crc >>> 0, 16);
  central.writeUInt32LE(declaredCompressed >>> 0, 20);
  central.writeUInt32LE(declaredSize >>> 0, 24);
  central.writeUInt16LE(name.length, 28);
  central.writeUInt16LE(0, 30);
  central.writeUInt16LE(0, 32);
  central.writeUInt16LE(0, 34);
  central.writeUInt16LE(0, 36);
  central.writeUInt32LE((entry.externalAttributes ?? (entry.directory ? 0x41ed0010 : 0x81a40000)) >>> 0, 38);
  central.writeUInt32LE((entry.localOffset ?? offset) >>> 0, 42);
  name.copy(central, 46);
  return { local: Buffer.concat([local, compressed]), central };
}

export function buildZip(entries, options = {}) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const entry of entries) {
    const built = zipEntry(entry, offset);
    locals.push(built.local);
    centrals.push(built.central);
    offset += built.local.length;
  }
  const central = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(options.entryCount ?? entries.length, 8);
  eocd.writeUInt16LE(options.entryCount ?? entries.length, 10);
  eocd.writeUInt32LE(options.centralSize ?? central.length, 12);
  eocd.writeUInt32LE(options.centralOffset ?? offset, 16);
  eocd.writeUInt16LE(0, 20);
  const result = Buffer.concat([...locals, central, eocd]);
  return options.trailing ? Buffer.concat([result, asBytes(options.trailing)]) : result;
}

function writeTarText(block, offset, length, value) {
  asBytes(value).copy(block, offset, 0, length);
}

function writeTarNumber(block, offset, length, value) {
  const text = Math.trunc(value).toString(8).padStart(length - 1, '0');
  writeTarText(block, offset, length, `${text}\0`);
}

function tarHeader(entry) {
  const block = Buffer.alloc(512);
  writeTarText(block, 0, 100, entry.name);
  writeTarNumber(block, 100, 8, entry.mode ?? (entry.directory ? 0o755 : 0o644));
  writeTarNumber(block, 108, 8, 0);
  writeTarNumber(block, 116, 8, 0);
  writeTarNumber(block, 124, 12, entry.size ?? asBytes(entry.content).length);
  writeTarNumber(block, 136, 12, 0);
  block.fill(0x20, 148, 156);
  block[156] = (entry.type ?? (entry.directory ? '5' : '0')).charCodeAt(0);
  writeTarText(block, 157, 100, entry.linkName ?? '');
  writeTarText(block, 257, 6, 'ustar\0');
  writeTarText(block, 263, 2, '00');
  writeTarText(block, 345, 155, entry.prefix ?? '');
  const checksum = block.reduce((sum, byte) => sum + byte, 0);
  writeTarText(block, 148, 8, `${checksum.toString(8).padStart(6, '0')}\0 `);
  if (entry.badChecksum) block[148] ^= 1;
  return block;
}

export function paxRecord(key, value) {
  const body = `${key}=${value}\n`;
  let length = Buffer.byteLength(body) + 2;
  while (Buffer.byteLength(`${length} ${body}`) !== length) length += 1;
  return Buffer.from(`${length} ${body}`);
}

export function buildTar(entries, options = {}) {
  const chunks = [];
  for (const entry of entries) {
    const content = asBytes(entry.content);
    chunks.push(tarHeader(entry), content);
    const padding = (512 - (content.length % 512)) % 512;
    if (padding) chunks.push(Buffer.alloc(padding));
  }
  if (!options.missingEnd) chunks.push(Buffer.alloc(options.oneEndBlock ? 512 : 1024));
  const result = Buffer.concat(chunks);
  return options.trailing ? Buffer.concat([result, asBytes(options.trailing)]) : result;
}

export function buildGzip(payload, options = {}) {
  const body = deflateRawSync(payload);
  const header = Buffer.from([0x1f, 0x8b, options.method ?? 8, 0, 0, 0, 0, 0, 0, 255]);
  const trailer = Buffer.alloc(8);
  trailer.writeUInt32LE(options.crc ?? crc32(payload), 0);
  trailer.writeUInt32LE(options.size ?? (payload.length >>> 0), 4);
  const result = Buffer.concat([header, body, trailer]);
  return options.trailing ? Buffer.concat([result, asBytes(options.trailing)]) : result;
}

export function buildTarGz(entries, options = {}) {
  return buildGzip(buildTar(entries, options.tar), options.gzip);
}

export const validZipEntries = Object.freeze([
  Object.freeze({ name: 'bin/', directory: true }),
  Object.freeze({ name: 'bin/CLIProxyAPI.exe', content: 'candidate', method: 8 }),
  Object.freeze({ name: 'README.txt', content: 'readme' })
]);

export const validTarEntries = Object.freeze([
  Object.freeze({ name: 'bin/', directory: true }),
  Object.freeze({ name: 'bin/CLIProxyAPI', content: 'candidate', mode: 0o755 }),
  Object.freeze({ name: 'README.txt', content: 'readme' })
]);

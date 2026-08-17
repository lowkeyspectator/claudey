import crypto from 'node:crypto';

const VERSION = /^\d+\.\d+\.\d+$/u;
const REVISION = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u;
const SHA256 = /^[0-9a-f]{64}$/u;

function failure() { const error = new Error('The SPDX inventory is unsafe.'); error.code = 'PACKAGE_UNSAFE'; return error; }

function exact(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return (prototype === Object.prototype || prototype === null)
    && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
}

function hash(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }

function canonical(value) { return Buffer.from(`${JSON.stringify(value)}\n`, 'utf8'); }

function checkedInventory(value) {
  if (!Array.isArray(value) || value.length === 0 || value.length > 10_000) throw failure();
  let prior = '';
  return value.map((entry) => {
    if (!exact(entry, ['path', 'sha256', 'size', 'mode']) || typeof entry.path !== 'string'
      || entry.path.length === 0 || entry.path.length > 512 || entry.path.includes('\\') || entry.path.startsWith('/')
      || entry.path.split('/').includes('..') || !SHA256.test(entry.sha256)
      || !Number.isSafeInteger(entry.size) || entry.size < 0 || ![0o644, 0o755].includes(entry.mode)
      || entry.path <= prior) throw failure();
    prior = entry.path;
    return entry;
  });
}

export function buildSpdxDocument({ managerVersion, sourceRevision, inventory } = {}) {
  try {
    if (!VERSION.test(managerVersion) || !REVISION.test(sourceRevision)) throw failure();
    const checked = checkedInventory(inventory);
    const files = checked.map((entry) => ({
    SPDXID: `SPDXRef-File-${hash(Buffer.from(entry.path)).slice(0, 24)}`,
    fileName: entry.path,
    checksums: [{ algorithm: 'SHA256', checksumValue: entry.sha256 }],
    licenseConcluded: 'NOASSERTION', licenseInfoInFiles: ['NOASSERTION'], copyrightText: 'NOASSERTION'
  }));
    const packageId = 'SPDXRef-Package-Claudey-Manager';
    const document = {
    spdxVersion: 'SPDX-2.3', dataLicense: 'CC0-1.0', SPDXID: 'SPDXRef-DOCUMENT',
    name: `claudey-manager-${managerVersion}`,
    documentNamespace: `https://github.com/ramsaijanapana/claudey/spdx/${managerVersion}/${sourceRevision}`,
    creationInfo: { created: '1970-01-01T00:00:00Z', creators: ['Tool: claudeyctl-sbom-1'] },
    packages: [{ SPDXID: packageId, name: 'claudey-manager', versionInfo: managerVersion,
      downloadLocation: 'NOASSERTION', filesAnalyzed: true, licenseConcluded: 'NOASSERTION',
      licenseDeclared: 'MIT', copyrightText: 'NOASSERTION' }],
    files,
    relationships: [
      { spdxElementId: 'SPDXRef-DOCUMENT', relationshipType: 'DESCRIBES', relatedSpdxElement: packageId },
      ...files.map((file) => ({ spdxElementId: packageId, relationshipType: 'CONTAINS', relatedSpdxElement: file.SPDXID }))
    ]
    };
    const bytes = canonical(document);
    const artifact = Object.freeze({ name: `claudey-manager-${managerVersion}.spdx.json`,
      sha256: hash(bytes), size: bytes.length });
    return Object.freeze({ bytes, descriptor: Object.freeze({ schemaVersion: 1, kind: 'manager-sbom',
      managerVersion, sourceRevision, artifact }) });
  } catch { throw failure(); }
}

/**
 * UUID core: parsing, validating, and layout conversion for RFC 4122 identifiers.
 *
 * Design decisions, stated plainly so the tests can lock them down:
 *
 * 1. Strict variant. Only the two top bits `10` (RFC 4122) are accepted. The other
 *    three variants (0xx NCS, 110 Microsoft, 111 reserved) are rejected by `parse()`.
 *    The `Variant` string union exists so callers can branch on the label without
 *    re-deriving it; `fromFields` refuses to mint a non-RFC variant.
 *
 * 2. Strict version. Versions 1–5 are recognized. Versions 6, 7, 8 exist in newer
 *    drafts but are NOT in RFC 4122; supporting them would mean guessing layout
 *    semantics the standard does not define. Reject them.
 *
 * 3. Case-insensitive input. RFC 4122 §3 uses lowercase in examples but the grammar
 *    allows hex in either case. `parse` lowercases before matching.
 *
 * 4. No urn: prefix. "urn:uuid:" is permitted by RFC 4122 §4 but handling it would
 *    double the surface area of the parser for a convenience callers can do in one
 *    line. One interpretation, tested.
 *
 * 5. Braces from Microsoft tooling `{...}` are accepted. This is a single
 *    well-defined transformation and avoids a whole class of copy-paste failures.
 *    We strip them, not advertised them: `serialize` never emits braces.
 */

/** The RFC 4122 variant label this library attaches to a parsed UUID. */
export const Variant = Object.freeze({
  /** RFC 4122 — two top bits `10`. The only variant `parse` will accept. */
  RFC_4122: 'rfc_4122',
});

/** The set of version strings this library recognizes. */
export const Version = Object.freeze({
  TIME_BASED: 'time_based',
  DCE_SECURITY: 'dce_security',
  NAME_MD5: 'name_md5',
  RANDOM: 'random',
  NAME_SHA1: 'name_sha1',
});

/** Canonical 8-4-4-4-12 hex form, lowercase, no braces, no urn prefix. */
export const CANONICAL_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const HEX = Array.from({ length: 256 }, (_, i) =>
  (i < 16 || (i >= 32 && i < 48)) ? null : i.toString(16).charCodeAt(0)
);

/** A validated RFC 4122 UUID broken into its six canonical fields. */
export class UUID {
  constructor(f) {
    this.timeLow = f.timeLow;
    this.timeMid = f.timeMid;
    this.timeHiAndVersion = f.timeHiAndVersion;
    this.clockSeqHiVar = f.clockSeqHiVar;
    this.clockSeqLow = f.clockSeqLow;
    this.node = f.node;
    Object.freeze(this);
  }

  /** Raw 4-bit version nibble from timeHiAndVersion (1–5 for RFC 4122). */
  get versionNumber() {
    return (this.timeHiAndVersion >> 12) & 0xf;
  }

  /** Human label for the version. */
  get version() {
    return versionLabel(this.versionNumber);
  }

  /** Always `rfc_4122` — parse() rejects anything else. */
  get variant() {
    return Variant.RFC_4122;
  }

  /** Canonical lowercase 8-4-4-4-12 string. */
  serialize() {
    const f = [this.timeLow, this.timeMid, this.timeHiAndVersion,
               this.clockSeqHiVar << 8 | this.clockSeqLow, this.node];
    const widths = [8, 4, 4, 4, 12];
    let s = '';
    let i = 0;
    for (const v of f) {
      s += (i > 0 ? '-' : '') + v.toString(16).padStart(widths[i], '0');
      i++;
    }
    return s;
  }
}

const VERSION_LABELS = {
  1: Version.TIME_BASED,
  2: Version.DCE_SECURITY,
  3: Version.NAME_MD5,
  4: Version.RANDOM,
  5: Version.NAME_SHA1,
};

function versionLabel(n) {
  return VERSION_LABELS[n] || 'unknown';
}

/**
 * Parse a UUID string into a frozen UUID object.
 *
 * Accepts canonical form, uppercase, and `{braced}` (Microsoft tooling) variants.
 * Rejects urn:uuid: prefixes, other variants (NCS/Microsoft/reserved), and
 * versions outside 1–5.
 *
 * @throws {Error} if the input is not a structurally valid RFC 4122 UUID.
 */
export function parse(s) {
  const norm = normalizeInput(s);
  if (!CANONICAL_RE.test(norm)) {
    throw new Error(`not a valid UUID string: ${JSON.stringify(s)}`);
  }

  const timeLow = parseIntHex(norm.slice(0, 8));
  const timeMid = parseIntHex(norm.slice(9, 13));
  const timeHiAndVersion = parseIntHex(norm.slice(14, 18));
  const clockSeq = parseIntHex(norm.slice(19, 23));
  const node = parseIntHex(norm.slice(24, 36));

  const clockSeqHiVar = (clockSeq >> 8) & 0xff;
  const clockSeqLow = clockSeq & 0xff;

  if ((clockSeqHiVar & 0xc0) !== 0x80) {
    throw new Error(`unsupported variant (top bits not '10'): ${JSON.stringify(s)}`);
  }
  const v = (timeHiAndVersion >> 12) & 0xf;
  if (v < 1 || v > 5) {
    throw new Error(`unsupported version ${v}: ${JSON.stringify(s)}`);
  }

  return new UUID({ timeLow, timeMid, timeHiAndVersion, clockSeqHiVar, clockSeqLow, node });
}

/**
 * Build a UUID from raw numeric fields. The caller is responsible for setting
 * the variant and version bits; fromFields validates them but does not force
 * them. This is the dual of parse() — useful for constructing a v4 from
 * cryptographic randomness without going through string form.
 */
export function fromFields(f) {
  if (typeof f !== 'object' || f === null) {
    throw new Error('fields must be an object');
  }
  for (const k of ['timeLow', 'timeMid', 'timeHiAndVersion', 'clockSeqHiVar', 'clockSeqLow', 'node']) {
    if (typeof f[k] !== 'number' || !Number.isInteger(f[k])) {
      throw new Error(`field ${k} must be an integer`);
    }
  }
  if (f.timeLow < 0 || f.timeLow > 0xffffffff) throw new Error('timeLow out of range');
  if (f.timeMid < 0 || f.timeMid > 0xffff) throw new Error('timeMid out of range');
  if (f.timeHiAndVersion < 0 || f.timeHiAndVersion > 0xffff) throw new Error('timeHiAndVersion out of range');
  if (f.clockSeqHiVar < 0 || f.clockSeqHiVar > 0xff) throw new Error('clockSeqHiVar out of range');
  if (f.clockSeqLow < 0 || f.clockSeqLow > 0xff) throw new Error('clockSeqLow out of range');
  if (f.node < 0 || f.node > 0xffffffffffff) throw new Error('node out of range');

  if ((f.clockSeqHiVar & 0xc0) !== 0x80) {
    throw new Error(`unsupported variant (clockSeqHiVar top bits not '10')`);
  }
  const v = (f.timeHiAndVersion >> 12) & 0xf;
  if (v < 1 || v > 5) {
    throw new Error(`unsupported version ${v}`);
  }

  return new UUID({ ...f });
}

function normalizeInput(s) {
  if (typeof s !== 'string') {
    throw new Error(`UUID input must be a string, got ${typeof s}`);
  }
  let r = s;
  if (r.length >= 2 && r.charCodeAt(0) === 0x7b && r.charCodeAt(r.length - 1) === 0x7d) {
    r = r.slice(1, -1);
  }
  return r.toLowerCase();
}

function parseIntHex(hex) {
  // Bitwise | truncates to 32 bits, which would corrupt the 48-bit node field.
  // Number() preserves full precision up to 2^53.
  return Number('0x' + hex);
}

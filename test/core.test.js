import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parse, fromFields, UUID, Variant, Version, CANONICAL_RE } from '../src/core.js';

// A canonical v4 UUID with the RFC 4122 variant bit set.
const V4 = '550e8400-e29b-41d4-a716-446655440000';

// Microsoft-braced form of the same UUID.
const V4_BRACED = '{550e8400-e29b-41d4-a716-446655440000}';

// Same UUID in uppercase — RFC grammar allows either case.
const V4_UPPER = '550E8400-E29B-41D4-A716-446655440000';

// A v1 (time-based) UUID.
const V1 = 'c232ab00-9414-11ec-b3c8-9f6bdecedce6';

// A v3 (name + MD5) UUID.
const V3 = '622fe1f2-fee0-3e9a-b29b-ae50af006e2c';

// A v5 (name + SHA1) UUID.
const V5 = '2c0d9d28-d27e-5b85-a941-3b5f8a72f560';

test('parse returns a UUID instance', () => {
  const u = parse(V4);
  assert.ok(u instanceof UUID);
  assert.equal(u.timeLow, 0x550e8400);
  assert.equal(u.timeMid, 0xe29b);
  assert.equal(u.timeHiAndVersion, 0x41d4);
  assert.equal(u.clockSeqHiVar, 0xa7);
  assert.equal(u.clockSeqLow, 0x16);
  assert.equal(u.node, 0x446655440000);
});

test('parse is case-insensitive', () => {
  assert.deepEqual(parse(V4_UPPER), parse(V4));
});

test('parse accepts the {braced} Microsoft form', () => {
  assert.deepEqual(parse(V4_BRACED), parse(V4));
});

test('parse rejects the urn:uuid: prefix', () => {
  assert.throws(() => parse('urn:uuid:' + V4), /not a valid UUID string/);
});

test('parse reports the RFC 4122 variant for all accepted UUIDs', () => {
  for (const s of [V1, V3, V4, V5]) {
    assert.equal(parse(s).variant, Variant.RFC_4122);
  }
});

test('parse extracts version 1, 3, 4, 5 correctly', () => {
  assert.equal(parse(V1).versionNumber, 1);
  assert.equal(parse(V1).version, Version.TIME_BASED);
  assert.equal(parse(V3).versionNumber, 3);
  assert.equal(parse(V3).version, Version.NAME_MD5);
  assert.equal(parse(V4).versionNumber, 4);
  assert.equal(parse(V4).version, Version.RANDOM);
  assert.equal(parse(V5).versionNumber, 5);
  assert.equal(parse(V5).version, Version.NAME_SHA1);
});

test('parse rejects a non-hex character', () => {
  assert.throws(() => parse('550e8400-e29b-41d4-a716-44665544000g'), /not a valid UUID string/);
});

test('parse rejects a string that is too short', () => {
  assert.throws(() => parse('550e8400-e29b-41d4-a716-44665544000'), /not a valid UUID string/);
});

test('parse rejects a non-RFC variant (NCS, top bit clear)', () => {
  // Flip the top bit of clock_seq_hi to 0 → variant becomes 0xx (NCS).
  // '27' has top bit clear; original was 'a7'.
  const ncs = '550e8400-e29b-41d4-2716-446655440000';
  assert.throws(() => parse(ncs), /unsupported variant/);
});

test('parse rejects the Microsoft reserved variant (111)', () => {
  // 'e7' = 1110 0111 → top three bits 111 = reserved variant.
  const ms = '550e8400-e29b-41d4-e716-446655440000';
  assert.throws(() => parse(ms), /unsupported variant/);
});

test('parse rejects an unsupported version (0)', () => {
  // Replace '4' in '41d4' with '0' → version nibble 0.
  const bad = '550e8400-e29b-01d4-a716-446655440000';
  assert.throws(() => parse(bad), /unsupported version 0/);
});

test('parse rejects an unsupported version (6)', () => {
  // Replace '4' with '6'.
  const v6 = '550e8400-e29b-61d4-a716-446655440000';
  assert.throws(() => parse(v6), /unsupported version 6/);
});

test('serialize produces the canonical lowercase form', () => {
  assert.equal(parse(V4).serialize(), V4);
});

test('serialize round-trips through parse for every supported version', () => {
  for (const s of [V1, V3, V4, V5]) {
    assert.equal(parse(s).serialize(), s);
  }
});

test('parse of a braced input still serializes without braces', () => {
  assert.equal(parse(V4_BRACED).serialize(), V4);
});

test('parse of uppercase input still serializes as lowercase', () => {
  assert.equal(parse(V4_UPPER).serialize(), V4);
});

test('fromFields reconstructs a UUID that parse would produce', () => {
  const ref = parse(V4);
  const u = fromFields({
    timeLow: ref.timeLow,
    timeMid: ref.timeMid,
    timeHiAndVersion: ref.timeHiAndVersion,
    clockSeqHiVar: ref.clockSeqHiVar,
    clockSeqLow: ref.clockSeqLow,
    node: ref.node,
  });
  assert.equal(u.serialize(), V4);
  assert.equal(u.versionNumber, 4);
  assert.equal(u.variant, Variant.RFC_4122);
});

test('fromFields rejects a non-RFC variant', () => {
  assert.throws(() => fromFields({
    timeLow: 0, timeMid: 0, timeHiAndVersion: 0x4000,
    clockSeqHiVar: 0x00, clockSeqLow: 0, node: 0,
  }), /unsupported variant/);
});

test('fromFields rejects an out-of-range node field', () => {
  assert.throws(() => fromFields({
    timeLow: 0, timeMid: 0, timeHiAndVersion: 0x4000,
    clockSeqHiVar: 0x80, clockSeqLow: 0,
    node: 0x1000000000000, // 2^48, one past max
  }), /node out of range/);
});

test('UUID instances are frozen', () => {
  const u = parse(V4);
  assert.ok(Object.isFrozen(u));
});

test('CANONICAL_RE matches a well-formed lowercase UUID', () => {
  assert.ok(CANONICAL_RE.test(V4));
});

test('CANONICAL_RE does not match an uppercase UUID (it is lowercase-only)', () => {
  assert.equal(CANONICAL_RE.test(V4_UPPER), false);
});

test('parse rejects non-string input', () => {
  assert.throws(() => parse(123), /must be a string/);
  assert.throws(() => parse(null), /must be a string/);
});

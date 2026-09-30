# UUID String Parser

Parses RFC 4122 UUID strings into structured fields with variant and version
validation, and serializes them back to canonical form.

```js
import { parse, fromFields } from 'uuid-string-parser';

const u = parse('550e8400-e29b-41d4-a716-446655440000');
u.versionNumber;  // 4
u.version;        // 'random'
u.variant;        // 'rfc_4122'
u.node;           // 0x446655440000
u.serialize();    // '550e8400-e29b-41d4-a716-446655440000'

const built = fromFields({
  timeLow: 0x550e8400, timeMid: 0xe29b, timeHiAndVersion: 0x41d4,
  clockSeqHiVar: 0xa7, clockSeqLow: 0x16, node: 0x446655440000,
});
built.serialize() === u.serialize();  // true
```

## Why

Working with UUIDs at the field level (extracting the version nibble, checking
the variant bits, reading the node field) usually means hand-slicing strings
and hoping you got the bit offsets right. This library does that once,
correctly, and hands back a frozen object you can branch on.

The trade-off is strictness: only the RFC 4122 variant (top two bits `10`) is
accepted, and only versions 1 through 5. Newer drafts define versions 6, 7, and
8, but their field layouts differ from RFC 4122 and supporting them would mean
inventing semantics. If you feed one in, `parse` throws rather than guess.

## Edge cases you will hit

- `urn:uuid:` prefixes are **rejected**. Strip them yourself first.
- `{braced}` strings from Microsoft tooling are accepted on input; `serialize`
  never emits braces.
- Uppercase hex is accepted on input; `serialize` always emits lowercase.
- The `node` field is 48 bits wide. Reading it with bitwise operators would
  silently truncate it to 32 bits — the implementation uses `Number()` instead,
  and exposes `node` as a safe integer.

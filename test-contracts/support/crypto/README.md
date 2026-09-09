<!--
This file is part of Compact.
Copyright (C) 2026 Midnight Foundation
SPDX-License-Identifier: Apache-2.0
-->

# Crypto fixture harness

Shared helpers for the `natives/keccak256`, `natives/secp256k1` and
`natives/sha256` fixtures, imported as `@test/crypto`. Nothing here is a
fixture: this directory holds no `.compact` file and no `*.test.ts`, so fixture
discovery walks past it.

Hex conversion, byte concatenation and number encoding come from
`@noble/hashes/utils.js` and `@noble/curves/utils.js` rather than being written
here; `@test/crypto` re-exports `bytesToHex` / `hexToBytes` so fixtures have one
import surface.

| module           | what it provides                                                             |
| ---------------- | ---------------------------------------------------------------------------- |
| `kat.ts`         | `runKat` — runs every vector, then fails once with an aggregated message     |
| `vectors.ts`     | the `Bytes<N>` width sweep both hash features share, plus `checkWidthVector` |
| `wycheproof.ts`  | Wycheproof loader, strict DER parser, vector classifier, `runWycheproofKat`  |
| `eth-address.ts` | `ethereum/tests` key-to-address vectors                                      |
| `data/`          | the vendored JSON, with provenance and checksums in its own README           |

## Which oracle is actually independent

A known-answer test is only worth what its reference is worth, and that differs
per feature:

- **`persistentHash` (SHA-256)** — the runtime routes it to the Rust on-chain
  runtime, so an expected digest computed with `@noble/hashes` is a genuine
  second implementation. Use `computed` / `sweepVectors`.
- **`keccak256`** — the runtime implements it as `keccak_256(toBinaryRepr(...))`
  over the very same `@noble/hashes` this package depends on. A computed digest
  therefore tests `toBinaryRepr`, the CompactType-to-bytes encoding, and nothing
  about the hash core. Use `pinned` with published digests wherever the core is
  the thing under test.
- **`secp256k1EcdsaVerify`** — the ECDSA equations live in Compact
  (`compiler/zkir-v3-library.compact`), so `@noble/curves`' own `verify` is an
  independent implementation of the protocol; only the field arithmetic is
  shared. Both it and Wycheproof's curated verdict back every driven vector.

## Writing a fixture

Runtime callbacks receive the generated `pureCircuits` as their second argument,
so a fixture over pure circuits never instantiates the contract:

```ts
import { keccak_256 } from '@noble/hashes/sha3.js';

import type { Contract, PureCircuits } from './.build/contract/index.js';
import { defineRuntimeTest } from '@test/compact-test';
import {
    checkWidthVector,
    runKat,
    sweepVectors,
    vectorLabel,
} from '@test/crypto';

const vectors = sweepVectors(keccak_256);

export default defineRuntimeTest<typeof Contract, PureCircuits>(
    import.meta.url,
    (_Contract, pure) => {
        runKat('keccak256 multi-length', vectors, vectorLabel, (vector) =>
            checkWidthVector(pure, vector),
        );
    },
);
```

## Pinned corpus coverage

`runEcdsaKat` reports its bucket split only when something fails, so the two
secp256k1 fixtures also call `assertCoverage`, which pins the split: 463
vectors, 244 driven, 217 excluded for encoding, 2 for malleability. Coverage
that is invisible while green can erode silently -- a corpus refresh, or a
stricter signature decoder, would shrink `driven` while every remaining vector
still passed. The pin makes that an explicit update, next to the checksums in
`data/README.md`.

## The fixtures

| fixture                                                 | what it covers                                                        |
| ------------------------------------------------------- | --------------------------------------------------------------------- |
| `natives/keccak256/known_vectors`                       | published digests -- the one keccak oracle independent of the runtime |
| `natives/keccak256/multi_length`                        | the width sweep, i.e. `toBinaryRepr` across packing boundaries        |
| `natives/keccak256/flatten_equivalence`                 | field structure is invisible to the digest                            |
| `natives/keccak256/trailing_zero`                       | trailing `0x00` is hashed, not trimmed                                |
| `natives/keccak256/cross_width`                         | zero padding keeps declared widths distinct                           |
| `natives/keccak256/field_types`                         | the 32-byte little-endian `Field` encoding, plus collision guards     |
| `natives/keccak256/ordinary_types`                      | shape, determinism, distinctness per type family                      |
| `natives/keccak256/{impure_without_v3, impure_with_v3}` | the zkir-v2 keccak gate, both directions                              |
| `natives/keccak256/adt_rejected`                        | ADT types rejected, with the v3 flag so the gate is not what fires    |
| `natives/secp256k1/requires_zkir_v3`                    | the whole secp stdlib is v3-gated                                     |
| `natives/secp256k1/ecdsa_verify`                        | the Wycheproof KAT, plus the off-circuit recovery round trip          |
| `natives/secp256k1/bitcoin_kat`                         | the same corpus with SHA-256 in-circuit                               |
| `natives/secp256k1/ethereum_address`                    | the canonical `ethereum/tests` addresses                              |
| `natives/secp256k1/slow/*`                              | provable lowering and key generation                                  |
| `natives/sha256/{multi_length, trailing_zero}`          | the width sweep and the no-trim guarantee                             |

Two things the fixture layout forces, both inherited from "one `.compact` per
fixture directory":

- A source compiled at two different flag settings — `keccak256` with and
  without `--feature-zkir-v3`, say — needs two fixture directories, each with
  its own copy of the contract.
- A case that drives two contracts splits into two fixtures.

A fixture whose compile takes more than ten seconds belongs under a `slow/`
path segment, which makes the orchestrator compile it exclusively. Of the
crypto fixtures only the two provable secp256k1 ones qualify, at 29s and 90s of
proving-key generation; the provable keccak256 fixture compiles in under three
and stays out.

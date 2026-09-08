// This file is part of Compact.
// Copyright (C) 2026 Midnight Foundation
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//  	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import { fromHex, toHex } from './hex.ts';

/**
 * Digest vectors over a sweep of `Bytes<N>` widths, shared by the keccak256 and
 * persistentHash (SHA-256) fixtures.
 *
 * ORACLE INDEPENDENCE — read before choosing between `computed` and `pinned`:
 *
 * `persistentHash` is implemented by the Rust on-chain runtime
 * (`built-ins.ts`, `ocrt.persistentHash`), so a digest computed here with
 * `@noble/hashes` is a genuine second implementation and `computed` vectors
 * carry their weight.
 *
 * `keccak256` is NOT: the JS runtime implements it as
 * `keccak_256(toBinaryRepr(...))` over the very same `@noble/hashes` this
 * package depends on. A `computed` keccak vector therefore tests `toBinaryRepr`
 * — the CompactType-to-bytes encoding, which is exactly what the trailing-zero
 * and field-encoding fixtures are about — and tells you nothing about the hash
 * core. Pin published digests with `pinned` wherever the hash core itself is
 * the thing under test.
 */

/** A `Bytes<N>` input paired with its expected digest. */
export type LengthVector = {
    /** Input bytes as lowercase hex; its byte length picks the `Bytes<N>` circuit. */
    input: string;
    /** Expected digest of `input`, as a 64-character lowercase hex string. */
    digest: string;
    /** Optional annotation, appended to the `Bytes<N>` identity in failures. */
    label?: string;
};

/** A hash function over raw bytes — `keccak_256` or `sha256` from @noble/hashes. */
export type DigestFn = (input: Uint8Array) => Uint8Array;

/**
 * The width sweep both hash features cover:
 *
 * - `1` — the minimal single-byte input.
 * - `32..63` — every width from the digest width through one byte past the
 *   2x31 = 62 field-element packing boundary. 33 is also the compressed
 *   secp256k1 public-key length.
 * - `93`, `94` — straddling the 3x31 packing multiple.
 * - `376` — the CCTP V2 burn-message length, a real-world size.
 */
export const packingWidths: readonly number[] = [
    1,
    ...Array.from({ length: 32 }, (_unused, index) => 32 + index),
    93,
    94,
];

/** Widths past the packing sweep: a real-world size and a multi-block input. */
export const largeWidths: readonly number[] = [376, 1024];

/** Every width the shared `multi_length` contracts are expected to export. */
export const sweepWidths: readonly number[] = [
    ...packingWidths,
    ...largeWidths,
];

/**
 * The deterministic filler: `byte i = (i % 255) + 1`.
 *
 * Every byte is nonzero, which matters for `persistentHash`: a `Bytes<N>` is
 * serialized with its trailing `0x00` run trimmed (`CompactTypeBytes.toValue`),
 * so an all-nonzero input hashes the same N bytes off-circuit and in-circuit
 * without depending on how the trim is undone. Fixtures that mean to exercise
 * the trailing-zero behaviour build their inputs directly instead.
 */
export function fillerBytes(length: number): Uint8Array {
    return Uint8Array.from({ length }, (_unused, index) => (index % 255) + 1);
}

/**
 * Builds a vector whose expected digest is COMPUTED by `digest`.
 *
 * Sound for `persistentHash`; for `keccak256` see the oracle note above.
 */
export function computed(
    digest: DigestFn,
    input: Uint8Array,
    label?: string,
): LengthVector {
    const vector: LengthVector = {
        input: toHex(input),
        digest: toHex(digest(input)),
    };

    if (label !== undefined) {
        vector.label = label;
    }

    return vector;
}

/**
 * Builds a vector whose expected digest is a PUBLISHED constant, independent of
 * any implementation this package can reach. The only oracle that tests a hash
 * core the runtime shares with `@noble/hashes`.
 */
export function pinned(
    input: Uint8Array | string,
    digest: string,
    label?: string,
): LengthVector {
    const bytes = typeof input === 'string' ? fromHex(input) : input;
    const vector: LengthVector = { input: toHex(bytes), digest };

    if (label !== undefined) {
        vector.label = label;
    }

    return vector;
}

/**
 * The filler-input vector for every width in `widths`, with digests computed by
 * `digest`. A fixture appends its own hand-written or pinned vectors.
 */
export function sweepVectors(
    digest: DigestFn,
    widths: readonly number[] = sweepWidths,
): LengthVector[] {
    return widths.map((width) => computed(digest, fillerBytes(width)));
}

/** The `Bytes<N>` width a vector drives. */
export function vectorWidth(vector: LengthVector): number {
    return vector.input.length / 2;
}

/** Short vector identity for failure messages, e.g. `Bytes<62> (CCTP)`. */
export function vectorLabel(vector: LengthVector): string {
    const width = `Bytes<${vectorWidth(vector)}>`;

    return vector.label === undefined ? width : `${width} (${vector.label})`;
}

/**
 * Resolves the `hashBytes{N}` circuit a vector drives, failing with the width
 * that is missing rather than `circuit is not a function`.
 */
export function widthCircuit(
    pureCircuits: Record<string, unknown>,
    width: number,
): (value: Uint8Array) => Uint8Array {
    const name = `hashBytes${width}`;
    const circuit = pureCircuits[name];

    if (typeof circuit !== 'function') {
        throw new Error(
            `contract exposes no ${name} circuit; add it to the fixture contract or drop Bytes<${width}> from the sweep`,
        );
    }

    return circuit as (value: Uint8Array) => Uint8Array;
}

/**
 * Drives one vector through its `hashBytes{N}` circuit and compares the digest.
 * Throws with both digests on a mismatch; used as the `check` of a `runKat`.
 */
export function checkWidthVector(
    pureCircuits: Record<string, unknown>,
    vector: LengthVector,
): void {
    const width = vectorWidth(vector);
    const circuit = widthCircuit(pureCircuits, width);
    const actual = circuit(fromHex(vector.input));

    if (!(actual instanceof Uint8Array) || actual.length !== 32) {
        throw new Error(
            `hashBytes${width} did not return a 32-byte digest (got ${String(actual)})`,
        );
    }

    if (toHex(actual) !== vector.digest) {
        throw new Error(
            `hashBytes${width} = 0x${toHex(actual)}, expected 0x${vector.digest}`,
        );
    }
}

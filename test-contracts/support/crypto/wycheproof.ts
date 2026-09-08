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

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';

import { fromHex } from './hex.ts';
import { buildReport, formatFailure, type KatOutcome } from './kat.ts';

/**
 * Loader and classifier for the Project Wycheproof secp256k1 / SHA-256 Bitcoin
 * ECDSA verification vectors vendored under `./data`.
 *
 * `secp256k1EcdsaVerify` takes `(r, s)` scalars and an `(x, y)` point directly:
 * it has no DER parser, and it performs the RAW ECDSA check with no low-s
 * (malleability) enforcement, accepting both `s` and `n - s`. So this module
 *
 *   1. strict-DER-parses each `sig` `SEQUENCE { INTEGER r, INTEGER s }`,
 *   2. parses the group's uncompressed `04 ‖ wx ‖ wy` key into `{x, y}`,
 *   3. precomputes the signed digest `e = SHA-256(msg)`, big-endian,
 *
 * and sorts every vector into one of three buckets:
 *
 *   - DRIVEN — feed `(e, {r, s}, pk)` to the circuit and assert the verdict.
 *   - SKIPPED (encoding) — the DER does not parse strictly, so the vector only
 *     exercises a parser the primitive does not have.
 *   - CARVED (malleability) — high-s signatures the raw primitive accepts but
 *     Bitcoin's low-s policy calls `invalid`. Detected by VALUE and BEHAVIOUR
 *     rather than by flag: of the two such vectors in this corpus only tcId 1
 *     carries `SignatureMalleabilityBitcoin`, while tcId 388 is flagged
 *     `ArithmeticError`, so a flag-based carve would miss it.
 *
 * Both excluded buckets are returned as counts, so a fixture reports what it
 * deliberately did not cover instead of silently overstating coverage.
 *
 * ORACLE INDEPENDENCE: unlike keccak256, the ECDSA equations here are NOT
 * shared with the reference. `secp256k1EcdsaVerify` is a Compact circuit
 * (`compiler/zkir-v3-library.compact`) composed from `inv` / `ecMulGenerator` /
 * `ecAdd` / `secp256k1PointX`; `@noble/curves`' own `verify` is an independent
 * implementation of the protocol, sharing only the field arithmetic underneath.
 * Every driven expectation is backed by BOTH that raw verdict and Wycheproof's
 * curated `result`, so a mismatch is a real finding.
 */

/**
 * Mirrors the compact-runtime `Secp256k1Point` shape: affine `(x, y)` plus the
 * explicit point-at-infinity flag the runtime type-checks for (`x = y = 0` when
 * `identity` is set).
 */
export type Secp256k1Point = {
    x: bigint;
    y: bigint;
    identity: boolean;
};

/** The point at infinity, in the representation the runtime requires. */
export const IDENTITY_POINT: Secp256k1Point = {
    x: 0n,
    y: 0n,
    identity: true,
};

export type EcdsaScalars = {
    r: bigint;
    s: bigint;
};

export type WycheproofResult = 'valid' | 'invalid';

export type WycheproofTest = {
    tcId: number;
    comment: string;
    flags?: string[];
    /** Hex-encoded message. */
    msg: string;
    /** Hex-encoded DER signature. */
    sig: string;
    result: WycheproofResult;
};

export type WycheproofGroup = {
    type: string;
    publicKey: {
        uncompressed: string;
        wx: string;
        wy: string;
    };
    sha: string;
    tests: WycheproofTest[];
};

export type WycheproofRoot = {
    algorithm: string;
    numberOfTests: number;
    testGroups: WycheproofGroup[];
};

export const VECTORS_FILENAME = 'ecdsa_secp256k1_sha256_bitcoin_test.json';

const dataDir = path.join(path.dirname(fileURLToPath(import.meta.url)), 'data');

// secp256k1 group order `n` and `n / 2`, the low-s threshold. A signature is
// high-s (malleable) when `n / 2 < s < n`.
const CURVE_ORDER: bigint = secp256k1.Point.Fn.ORDER;
const HALF_ORDER: bigint = CURVE_ORDER >> 1n;

/**
 * The corpus vectors whose recomputed verification point `P = u1*G + u2*pk` is
 * the point at infinity; Wycheproof marks all five `invalid`:
 *
 *   386 point at infinity during verify     424 duplication bug
 *   425 comparison with point at infinity   439, 440 public key shares an
 *                                           x-coordinate with the generator
 *
 * `P` has no x-coordinate to compare against `r`, so the circuit fails with
 * `cannot extract the x-coordinate of the secp256k1 identity point` instead of
 * returning `false`. They are still driven, expecting that failure.
 */
const IDENTITY_POINT_TC_IDS: ReadonlySet<number> = new Set([
    386, 424, 425, 439, 440,
]);

/** The failure raised when the verification point is the point at infinity. */
export const IDENTITY_ABORT_MESSAGE =
    'cannot extract the x-coordinate of the secp256k1 identity point';

/** A vector whose signature parses cleanly, ready to drive a circuit. */
export type DrivenVector = {
    tcId: number;
    comment: string;
    groupIndex: number;
    flags: string[];
    /** Raw message bytes, variable length: the input to `e = SHA-256(msg)`. */
    msg: Uint8Array;
    /** Precomputed digest `e = SHA-256(msg)`, big-endian, 32 bytes. */
    e: Uint8Array;
    sig: EcdsaScalars;
    pk: Secp256k1Point;
    /**
     * Expected verdict for the raw, no-low-s circuit. Jointly backed by
     * Wycheproof's curated `result` and `@noble/curves`' raw ECDSA verdict,
     * which agree on every driven vector.
     *
     * Meaningless when `expectsIdentityAbort` is set: such a vector has no
     * returned verdict to compare against.
     */
    expectedValid: boolean;
    /** True for the identity-point vectors, which fail instead of returning. */
    expectsIdentityAbort: boolean;
};

export type ClassifiedVectors = {
    total: number;
    driven: DrivenVector[];
    /** Vectors skipped because the DER does not parse strictly. */
    skippedEncoding: {
        count: number;
        byFlag: Record<string, number>;
    };
    /** High-s vectors the raw circuit accepts but Bitcoin rejects. */
    carvedMalleability: {
        count: number;
        tcIds: number[];
    };
    /** Driven vectors expected to abort on an identity verification point. */
    identityAbort: {
        count: number;
        tcIds: number[];
    };
};

/** Thrown by the strict DER parser; means "skip this vector (encoding)". */
export class DerParseError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'DerParseError';
    }
}

/**
 * Parses one DER INTEGER at `offset`, returning `[value, nextOffset]`. Strict:
 * short-form length only, minimal non-negative encoding, no truncation.
 */
function parseDerInteger(bytes: Uint8Array, offset: number): [bigint, number] {
    if (offset + 2 > bytes.length) {
        throw new DerParseError('truncated INTEGER header');
    }

    if (bytes[offset] !== 0x02) {
        throw new DerParseError(
            `expected INTEGER tag, got 0x${bytes[offset]!.toString(16)}`,
        );
    }

    const length = bytes[offset + 1]!;

    if (length & 0x80) {
        throw new DerParseError('long-form length not allowed');
    }

    const start = offset + 2;
    const end = start + length;

    if (end > bytes.length) {
        throw new DerParseError('truncated INTEGER body');
    }

    if (length === 0) {
        throw new DerParseError('empty INTEGER');
    }

    const content = bytes.subarray(start, end);

    if (content[0]! & 0x80) {
        throw new DerParseError('negative INTEGER (high bit set)');
    }

    if (content[0] === 0x00 && (content.length < 2 || !(content[1]! & 0x80))) {
        throw new DerParseError(
            'non-minimal INTEGER (superfluous leading zero)',
        );
    }

    let value = 0n;

    for (const byte of content) {
        value = (value << 8n) | BigInt(byte);
    }

    return [value, end];
}

/**
 * Strictly parses a DER `SEQUENCE { INTEGER r, INTEGER s }` into its two
 * scalars. Throws `DerParseError` on any deviation (BER, long-form lengths,
 * non-minimal integers, trailing bytes, truncation) — exactly the cases the
 * missing DER parser would have to reject.
 */
export function strictParseEcdsaDer(sigHex: string): EcdsaScalars {
    let bytes: Uint8Array;

    try {
        bytes = fromHex(sigHex);
    } catch (error) {
        throw new DerParseError(
            error instanceof Error ? error.message : String(error),
        );
    }

    if (bytes.length < 2 || bytes[0] !== 0x30) {
        throw new DerParseError('expected SEQUENCE');
    }

    const length = bytes[1]!;

    if (length & 0x80) {
        throw new DerParseError('long-form SEQUENCE length not allowed');
    }

    if (2 + length !== bytes.length) {
        throw new DerParseError('SEQUENCE length mismatch / trailing bytes');
    }

    const [r, afterR] = parseDerInteger(bytes, 2);
    const [s, afterS] = parseDerInteger(bytes, afterR);

    if (afterS !== bytes.length) {
        throw new DerParseError('trailing bytes after s');
    }

    return { r, s };
}

/**
 * Parses a SEC1 public key into the runtime's affine `{x, y, identity}` shape.
 *
 * Two encodings denote a point: `00` is the point at infinity, and
 * `04 ‖ wx(32) ‖ wy(32)` is an uncompressed affine point. The uncompressed form
 * has no dedicated infinity encoding, but `(0, 0)` is not on the curve and is
 * how the runtime spells the identity, so it decodes as such rather than
 * passing through as a bogus affine point. Anything else is malformed.
 */
export function parseUncompressedPublicKey(
    uncompressed: string,
): Secp256k1Point {
    if (uncompressed === '00') {
        return IDENTITY_POINT;
    }

    if (uncompressed.length !== 130 || !uncompressed.startsWith('04')) {
        throw new Error(
            `unexpected uncompressed public key: ${uncompressed.slice(0, 10)}...`,
        );
    }

    const x = BigInt(`0x${uncompressed.slice(2, 66)}`);
    const y = BigInt(`0x${uncompressed.slice(66, 130)}`);

    return x === 0n && y === 0n ? IDENTITY_POINT : { x, y, identity: false };
}

/** True when `s` lies in the upper half `(n/2, n)`: a malleable, high-s value. */
function isHighS(s: bigint): boolean {
    return s > HALF_ORDER && s < CURVE_ORDER;
}

/**
 * The RAW ECDSA verdict (no low-s enforcement) over the big-endian digest `e`,
 * from `@noble/curves` — an independent implementation of the same protocol the
 * Compact circuit spells out. Out-of-range `r`/`s` are rejected, mirroring the
 * `Secp256k1Scalar` input type; the identity key, an off-curve point, or any
 * internal error is `false`.
 */
export function rawEcdsaVerify(
    e: Uint8Array,
    { r, s }: EcdsaScalars,
    pk: Secp256k1Point,
): boolean {
    if (r <= 0n || r >= CURVE_ORDER || s <= 0n || s >= CURVE_ORDER) {
        return false;
    }

    // The point at infinity is not a valid public key, and noble has no affine
    // encoding for it, so reject before lifting rather than via the catch.
    if (pk.identity) {
        return false;
    }

    try {
        const sigBytes = new secp256k1.Signature(r, s).toBytes('compact');
        const pubBytes = secp256k1.Point.fromAffine({
            x: pk.x,
            y: pk.y,
        }).toBytes(false);

        return secp256k1.verify(sigBytes, e, pubBytes, {
            prehash: false,
            lowS: false,
        });
    } catch {
        return false;
    }
}

/** Reads and parses the vendored Bitcoin test-vector file. */
export function loadBitcoinTestVectors(): WycheproofRoot {
    return JSON.parse(
        fs.readFileSync(path.join(dataDir, VECTORS_FILENAME), 'utf8'),
    ) as WycheproofRoot;
}

/**
 * Splits the Bitcoin vectors into the buckets described at the top of this file.
 */
export function classifyBitcoinVectors(
    root: WycheproofRoot = loadBitcoinTestVectors(),
): ClassifiedVectors {
    const driven: DrivenVector[] = [];
    const skipByFlag: Record<string, number> = {};
    const carvedTcIds: number[] = [];
    const identityAbortTcIds: number[] = [];
    let skipCount = 0;
    let total = 0;

    root.testGroups.forEach((group, groupIndex) => {
        const pk = parseUncompressedPublicKey(group.publicKey.uncompressed);

        for (const test of group.tests) {
            total += 1;

            const flags = test.flags ?? [];
            let sig: EcdsaScalars;

            try {
                sig = strictParseEcdsaDer(test.sig);
            } catch (error) {
                if (!(error instanceof DerParseError)) {
                    throw error;
                }

                skipCount += 1;

                for (const flag of flags) {
                    skipByFlag[flag] = (skipByFlag[flag] ?? 0) + 1;
                }

                continue;
            }

            const msg = fromHex(test.msg);
            const e = sha256(msg);
            const expectedValid = test.result === 'valid';
            const rawValid = rawEcdsaVerify(e, sig, pk);

            // Where the raw verdict diverges from Wycheproof's Bitcoin verdict,
            // the circuit cannot reproduce the answer. By construction that is
            // exactly a high-s malleability case; carve it. Any other
            // divergence is a genuine discrepancy between noble and the corpus,
            // so fail loudly rather than hide it behind a silent skip.
            if (rawValid !== expectedValid) {
                if (rawValid && !expectedValid && isHighS(sig.s)) {
                    carvedTcIds.push(test.tcId);
                    continue;
                }

                throw new Error(
                    `Unexpected raw-ECDSA vs Wycheproof divergence at tcId ${test.tcId} ` +
                        `(${test.comment}) [${flags.join(', ')}]: noble raw verdict ${rawValid}, ` +
                        `Wycheproof ${expectedValid}, high-s=${isHighS(sig.s)}. This is not a ` +
                        'low-s malleability case; investigate before trusting the KAT.',
                );
            }

            const expectsIdentityAbort = IDENTITY_POINT_TC_IDS.has(test.tcId);

            if (expectsIdentityAbort) {
                identityAbortTcIds.push(test.tcId);
            }

            driven.push({
                tcId: test.tcId,
                comment: test.comment,
                groupIndex,
                flags,
                msg,
                e,
                sig,
                pk,
                expectedValid,
                expectsIdentityAbort,
            });
        }
    });

    return {
        total,
        driven,
        skippedEncoding: { count: skipCount, byFlag: skipByFlag },
        carvedMalleability: {
            count: carvedTcIds.length,
            tcIds: carvedTcIds,
        },
        identityAbort: {
            count: identityAbortTcIds.length,
            tcIds: identityAbortTcIds,
        },
    };
}

/** Drives one classified vector through a circuit, returning its verdict. */
export type WycheproofDriver = (vector: DrivenVector) => boolean;

/**
 * The `Secp256k1Scalar` input type rejects `r`/`s` outside `[0, n)` before the
 * circuit runs. As far as the primitive is concerned such a vector is simply an
 * invalid signature, so a driver folds this into a `false` verdict rather than
 * letting the type-check surface as an unexpected failure.
 */
export function isScalarRangeRejection(error: unknown): boolean {
    const message = error instanceof Error ? error.message : String(error);

    return /argument 2|Secp256k1EcdsaSignature|Secp256k1Scalar/i.test(message);
}

/**
 * Runs `drive` over every driven vector and asserts each verdict.
 *
 * Identity-point vectors are asserted to FAIL, and to fail for the right
 * reason: a returned verdict, or a failure carrying any other message, is still
 * a finding. A driver that throws unexpectedly does not abort the corpus —
 * every remaining vector still runs, so the summary reports the full picture
 * rather than the first casualty.
 *
 * The counts for the buckets this corpus excludes are appended to the failure
 * message, so a fixture never reports coverage it did not have.
 */
export function runWycheproofKat(
    label: string,
    drive: WycheproofDriver,
    notes: string[] = [],
): ClassifiedVectors {
    const classified = classifyBitcoinVectors();
    const {
        total,
        driven,
        skippedEncoding,
        carvedMalleability,
        identityAbort,
    } = classified;
    const outcomes: KatOutcome[] = [];

    for (const vector of driven) {
        const expected = vector.expectsIdentityAbort
            ? 'abort'
            : vector.expectedValid
              ? 'valid'
              : 'invalid';
        const vectorLabel = `tcId ${vector.tcId} (${vector.comment})`;
        let got: boolean;

        try {
            got = drive(vector);
        } catch (error) {
            const message =
                error instanceof Error ? error.message : String(error);

            outcomes.push(
                expected === 'abort' && message.includes(IDENTITY_ABORT_MESSAGE)
                    ? { label: vectorLabel, ok: true }
                    : {
                          label: vectorLabel,
                          ok: false,
                          detail: `expected ${expected}, failed instead: ${message}`,
                      },
            );
            continue;
        }

        outcomes.push(
            expected === (got ? 'valid' : 'invalid')
                ? { label: vectorLabel, ok: true }
                : {
                      label: vectorLabel,
                      ok: false,
                      detail: `expected ${expected}, got ${got}`,
                  },
        );
    }

    const report = buildReport(label, outcomes);
    const coverage = [
        `corpus:                ${total} vectors`,
        `driven:                ${driven.length}`,
        `of which expect abort: ${identityAbort.count} (identity verification point; tcIds ${identityAbort.tcIds.join(', ') || '-'})`,
        `skipped (encoding):    ${skippedEncoding.count}`,
        `carved (malleability): ${carvedMalleability.count} (tcIds ${carvedMalleability.tcIds.join(', ') || '-'})`,
        ...notes,
    ];

    if (report.failed.length > 0) {
        throw new Error(
            `${formatFailure(report, { notes: coverage })}\n` +
                "  Each driven expectation is backed by both Wycheproof's result and noble's raw\n" +
                '  ECDSA check, so any mismatch is a real discrepancy in secp256k1EcdsaVerify.',
        );
    }

    return classified;
}

/**
 * The bucket sizes of the vendored corpus, as classified above.
 *
 * Pinned because coverage that is only reported on failure can erode silently:
 * a corpus refresh, or a change to the DER parser that rejects more vectors,
 * would shrink `driven` while every remaining vector still passed. Asserting
 * the split turns that into a failure you have to look at and update
 * deliberately, alongside the checksums in `data/README.md`.
 */
export const BITCOIN_CORPUS_COVERAGE = {
    total: 463,
    driven: 226,
    skippedEncoding: 235,
    carvedMalleability: 2,
    identityAbort: 5,
} as const;

/** Fails when the classified buckets drift from {@link BITCOIN_CORPUS_COVERAGE}. */
export function assertBitcoinCoverage(classified: ClassifiedVectors): void {
    const actual = {
        total: classified.total,
        driven: classified.driven.length,
        skippedEncoding: classified.skippedEncoding.count,
        carvedMalleability: classified.carvedMalleability.count,
        identityAbort: classified.identityAbort.count,
    };
    const drift = Object.entries(BITCOIN_CORPUS_COVERAGE)
        .filter(([key, want]) => actual[key as keyof typeof actual] !== want)
        .map(
            ([key, want]) =>
                `${key}: expected ${want}, got ${actual[key as keyof typeof actual]}`,
        );

    if (drift.length > 0) {
        throw new Error(
            `Wycheproof corpus coverage drifted (${drift.join('; ')}). If the vectors were ` +
                'refreshed, update BITCOIN_CORPUS_COVERAGE and the checksums in ' +
                'support/crypto/data/README.md together.',
        );
    }
}

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

import type { Secp256k1Point } from '@midnight-ntwrk/compact-runtime';
import { DER } from '@noble/curves/abstract/weierstrass.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { bytesToNumberBE } from '@noble/curves/utils.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hexToBytes } from '@noble/hashes/utils.js';

import {
    loadCorpus,
    runCorpusKat,
    type Classified,
    type Coverage,
    type CorpusRoot,
    type CorpusTest,
    type DrivenVector,
    type Excluded,
    type Expectation,
} from './corpus.ts';

// ECDSA verify corpora (secp256k1, secp256r1). Signatures are DER, keys are
// uncompressed `04 || wx || wy`, and the message is hashed before verifying.
// EdDSA shares none of that and belongs in a sibling module.
//
// The Compact primitive takes (r, s) scalars and an (x, y) point directly, so
// this module DER-decodes each signature, decodes the key, and precomputes the
// digest. Vectors it cannot ask the circuit about are excluded by reason.

type EcdsaGroup = {
    type: string;
    publicKey: { uncompressed: string; wx: string; wy: string };
    sha?: string;
    tests: CorpusTest[];
};

type EcdsaSuite = {
    /** Short identity for reports. */
    name: string;
    vectorsFile: string;
    /** The @noble/curves reference. `secp256k1` and `p256` are interchangeable here. */
    curve: typeof secp256k1;
    hash: (msg: Uint8Array) => Uint8Array;
    /**
     * True when the corpus verdicts enforce low-s but the circuit does not, so
     * valid high-s signatures must be excluded. Bitcoin only; the secp256r1
     * corpora are raw ECDSA.
     */
    enforcesLowS: boolean;
    /** tcIds whose verification point is the identity, so the circuit aborts. */
    identityPointTcIds: ReadonlySet<number>;
    /** Failure messages the circuit may legitimately abort with. */
    abortMessages: string[];
    coverage: Coverage;
};

export const SECP256K1_BITCOIN: EcdsaSuite = {
    name: 'secp256k1/SHA-256 (Bitcoin)',
    vectorsFile: 'ecdsa_secp256k1_sha256_bitcoin_test.json',
    curve: secp256k1,
    hash: sha256,
    enforcesLowS: true,
    identityPointTcIds: new Set([386, 424, 425, 439, 440]),
    abortMessages: [
        // The verification point is the identity, which has no x-coordinate.
        'cannot extract the x-coordinate of the secp256k1 identity point',
        // `w = inv(s)` has no result for s = 0.
        'Cannot compute inverse on input 0',
    ],
    coverage: {
        total: 463,
        driven: 244,
        excluded: { encoding: 217, malleability: 2 },
    },
};

type EcdsaScalars = {
    r: bigint;
    s: bigint;
};

/**
 * The point at infinity, as the runtime spells it. Weierstrass-only: affine
 * coordinates cannot express it, hence the flag. Edwards curves have no such
 * case, so this stays private to this module.
 */
const IDENTITY_POINT: Secp256k1Point = {
    x: 0n,
    y: 0n,
    identity: true,
};

export type EcdsaVector = DrivenVector & {
    flags: string[];
    /** Raw message bytes; the input to the digest. */
    msg: Uint8Array;
    /** Precomputed digest, big-endian. */
    e: Uint8Array;
    sig: EcdsaScalars;
    pk: Secp256k1Point;
    /** False when r or s is outside [0, n), which the argument type-check rejects. */
    scalarsInRange: boolean;
};

/**
 * Decode the DER `SEQUENCE { INTEGER r, INTEGER s }`, or undefined when it does
 * not parse. noble's parser is strict about the things that matter here --
 * minimal lengths, no leading zeros, no trailing bytes -- so a rejection means
 * the vector only exercises a parser the circuit does not have.
 */
function decodeSignature(sigHex: string): EcdsaScalars | undefined {
    try {
        return DER.toSig(hexToBytes(sigHex));
    } catch {
        return undefined;
    }
}

/**
 * Decode a SEC1 key. `00` is the point at infinity; otherwise
 * `04 || wx || wy`. The all-zero pair is how the runtime spells the identity.
 */
function parseUncompressedPublicKey(
    suite: EcdsaSuite,
    uncompressed: string,
): Secp256k1Point {
    if (uncompressed === '00') {
        return IDENTITY_POINT;
    }

    const size = suite.curve.Point.Fp.BYTES;

    if (
        uncompressed.length !== 2 + 4 * size ||
        !uncompressed.startsWith('04')
    ) {
        throw new Error(
            `unexpected uncompressed public key: ${uncompressed.slice(0, 10)}...`,
        );
    }

    // Deliberately not `Point.fromBytes`: that validates on-curve, and the
    // corpus is allowed to hand the circuit a key the circuit should reject.
    const body = hexToBytes(uncompressed.slice(2));
    const x = bytesToNumberBE(body.subarray(0, size));
    const y = bytesToNumberBE(body.subarray(size));

    return x === 0n && y === 0n ? IDENTITY_POINT : { x, y, identity: false };
}

/**
 * The raw ECDSA verdict from @noble, with low-s disabled. Independent of the
 * circuit: the ECDSA equations live in Compact, only field arithmetic is shared.
 */
function rawEcdsaVerify(
    suite: EcdsaSuite,
    e: Uint8Array,
    { r, s }: EcdsaScalars,
    pk: Secp256k1Point,
): boolean {
    const order = suite.curve.Point.Fn.ORDER;

    if (r <= 0n || r >= order || s <= 0n || s >= order || pk.identity) {
        return false;
    }

    try {
        const sig = new suite.curve.Signature(r, s).toBytes('compact');
        const key = suite.curve.Point.fromAffine({
            x: pk.x,
            y: pk.y,
        }).toBytes(false);

        return suite.curve.verify(sig, e, key, { prehash: false, lowS: false });
    } catch {
        return false;
    }
}

/**
 * Split a corpus into driven vectors and excluded ones.
 *
 * Excluded for `encoding` when the DER does not strictly parse, so the vector
 * only exercises a parser the circuit lacks. Excluded for `malleability` when
 * the raw verdict disagrees with the corpus because of low-s. Any other
 * disagreement throws: it would mean noble and the corpus genuinely differ.
 */
function classifyEcdsa(suite: EcdsaSuite): Classified<EcdsaVector> {
    const root = loadCorpus<CorpusRoot<EcdsaGroup>>(suite.vectorsFile);
    const order = suite.curve.Point.Fn.ORDER;
    const driven: EcdsaVector[] = [];
    const encoding: number[] = [];
    const malleability: number[] = [];
    let total = 0;

    for (const group of root.testGroups) {
        const pk = parseUncompressedPublicKey(
            suite,
            group.publicKey.uncompressed,
        );

        for (const test of group.tests) {
            total += 1;
            const sig = decodeSignature(test.sig);

            if (sig === undefined) {
                encoding.push(test.tcId);
                continue;
            }

            const msg = hexToBytes(test.msg);
            const e = suite.hash(msg);
            const expectedValid = test.result === 'valid';
            const rawValid = rawEcdsaVerify(suite, e, sig, pk);

            if (rawValid !== expectedValid) {
                const highS = new suite.curve.Signature(
                    sig.r,
                    sig.s,
                ).hasHighS();

                if (suite.enforcesLowS && rawValid && !expectedValid && highS) {
                    malleability.push(test.tcId);
                    continue;
                }

                throw new Error(
                    `${suite.name} tcId ${test.tcId} (${test.comment}): noble raw verdict ` +
                        `${rawValid}, corpus ${expectedValid}, high-s ${highS}. Not a low-s ` +
                        'case; investigate before trusting the KAT.',
                );
            }

            // The circuit aborts instead of returning a verdict when the
            // verification point is the identity, or when s = 0 leaves `inv(s)`
            // undefined. Both are `invalid` upstream, but neither yields a
            // boolean to compare.
            //
            // s = 0 only reaches `inv` when r is in range: the argument
            // type-check runs first, and an out-of-range r is rejected there,
            // which the caller reads as an invalid signature.
            const scalarsInRange = sig.r < order && sig.s < order;
            const aborts =
                suite.identityPointTcIds.has(test.tcId) ||
                (sig.s === 0n && scalarsInRange);
            const expectation: Expectation = aborts
                ? 'abort'
                : expectedValid
                  ? 'valid'
                  : 'invalid';

            driven.push({
                tcId: test.tcId,
                comment: test.comment,
                flags: test.flags ?? [],
                expectation,
                msg,
                e,
                sig,
                pk,
                scalarsInRange,
            });
        }
    }

    const excluded: Excluded[] = [
        { reason: 'encoding', tcIds: encoding },
        { reason: 'malleability', tcIds: malleability },
    ];

    return { total, driven, excluded };
}

/** Classify, then drive every vector and assert its expectation. */
export function runEcdsaKat(
    suite: EcdsaSuite,
    label: string,
    drive: (vector: EcdsaVector) => boolean,
    notes?: (classified: Classified<EcdsaVector>) => string[],
): Classified<EcdsaVector> {
    return runCorpusKat(
        `${label} [${suite.name}]`,
        classifyEcdsa(suite),
        drive,
        (error) =>
            error instanceof Error &&
            suite.abortMessages.some((message) =>
                error.message.includes(message),
            ),
        notes,
    );
}

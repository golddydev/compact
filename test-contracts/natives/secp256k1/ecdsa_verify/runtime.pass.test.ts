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

import { secp256k1EcdsaRecover } from '@midnight-ntwrk/compact-runtime';

import type { Contract, PureCircuits } from './.build/contract/index.js';
import { defineRuntimeTest } from '@test/compact-test';
import {
    assertBitcoinCoverage,
    classifyBitcoinVectors,
    isScalarRangeRejection,
    runWycheproofKat,
    type DrivenVector,
} from '@test/crypto';

// Two things, over the vendored Project Wycheproof secp256k1 / SHA-256 Bitcoin
// corpus (463 vectors; see support/crypto/data/README.md).
//
// 1. The KAT proper: drive `verifyEcdsa` with a digest hashed off-circuit, so
//    the only thing under test is the curve and scalar arithmetic. Each driven
//    verdict is backed by BOTH Wycheproof's curated result and @noble/curves'
//    raw ECDSA check. That reference is genuinely independent here: the ECDSA
//    equations live in Compact (`compiler/zkir-v3-library.compact`), so only the
//    field arithmetic underneath is shared.
//
// 2. The recovery round trip. `secp256k1EcdsaRecover` is not a circuit on this
//    toolchain -- the stdlib documents recovering off-circuit and verifying the
//    recovered key in-circuit (the EIP-1271 pattern). That is exactly what this
//    does, so the documented flow has coverage rather than being prose only.

/** The runtime's `Secp256k1Scalar` type-check rejects r/s outside [0, n). */
function drive(pure: PureCircuits, vector: DrivenVector): boolean {
    try {
        return pure.verifyEcdsa(vector.e, vector.sig, vector.pk);
    } catch (error) {
        if (isScalarRangeRejection(error)) {
            return false;
        }

        throw error;
    }
}

export default defineRuntimeTest<typeof Contract, PureCircuits>(
    import.meta.url,
    (_Contract, pure) => {
        assertBitcoinCoverage(
            runWycheproofKat(
                'secp256k1EcdsaVerify (pre-hashed digest)',
                (vector) => drive(pure, vector),
            ),
        );

        // Recover off-circuit, verify in-circuit. A valid signature has two
        // candidate recovery ids; the recovered key only has to verify, which is
        // the property the documented flow actually relies on.
        const valid = classifyBitcoinVectors().driven.filter(
            (vector) => vector.expectedValid && !vector.expectsIdentityAbort,
        );

        if (valid.length === 0) {
            throw new Error(
                'no valid Wycheproof vectors to drive the recovery round trip',
            );
        }

        const roundTripped = valid.filter((vector) =>
            [0, 1, 2, 3].some((recoveryId) => {
                let recovered;

                try {
                    recovered = secp256k1EcdsaRecover(
                        vector.e,
                        vector.sig,
                        recoveryId,
                    );
                } catch {
                    return false;
                }

                return drive(pure, { ...vector, pk: recovered });
            }),
        );

        if (roundTripped.length !== valid.length) {
            const missed = valid
                .filter((vector) => !roundTripped.includes(vector))
                .slice(0, 8)
                .map((vector) => `tcId ${vector.tcId}`)
                .join(', ');

            throw new Error(
                `recovery round trip: ${roundTripped.length}/${valid.length} valid ` +
                    `signatures produced a key that verifies in-circuit. Missed: ${missed}`,
            );
        }
    },
);

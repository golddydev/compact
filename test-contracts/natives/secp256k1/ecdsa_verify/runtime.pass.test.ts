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
    assertCoverage,
    runEcdsaKat,
    SECP256K1_BITCOIN,
    type EcdsaVector,
} from '@test/crypto';

// Two things over the Wycheproof corpus (see support/crypto/data/README.md).
//
// 1. The KAT: drive `verifyEcdsa` with an off-circuit digest, so only the curve
//    arithmetic is under test. Every expectation is backed by both the corpus
//    verdict and @noble/curves' raw check, which is independent here because the
//    ECDSA equations live in Compact.
//
// 2. The recovery round trip. `secp256k1EcdsaRecover` is not a circuit; the
//    stdlib says to recover off-circuit and verify the key in-circuit, so that
//    documented flow gets covered rather than only described.

// Out-of-range r/s never reach the circuit: the argument type-check rejects
// them, which for a caller just means an invalid signature.
function drive(pure: PureCircuits, vector: EcdsaVector): boolean {
    return (
        vector.scalarsInRange &&
        pure.verifyEcdsa(vector.e, vector.sig, vector.pk)
    );
}

export default defineRuntimeTest<typeof Contract, PureCircuits>(
    import.meta.url,
    (_Contract, pure) => {
        const classified = runEcdsaKat(
            SECP256K1_BITCOIN,
            'verifyEcdsa (pre-hashed digest)',
            (vector) => drive(pure, vector),
        );

        assertCoverage(
            SECP256K1_BITCOIN.name,
            classified,
            SECP256K1_BITCOIN.coverage,
        );

        const valid = classified.driven.filter(
            (vector) => vector.expectation === 'valid',
        );

        if (valid.length === 0) {
            throw new Error(
                'no valid vectors to drive the recovery round trip',
            );
        }

        // A valid signature has more than one candidate recovery id; the
        // recovered key only has to verify.
        const roundTripped = valid.filter((vector) =>
            [0, 1, 2, 3].some((recoveryId) => {
                try {
                    return drive(pure, {
                        ...vector,
                        pk: secp256k1EcdsaRecover(
                            vector.e,
                            vector.sig,
                            recoveryId,
                        ),
                    });
                } catch {
                    return false;
                }
            }),
        );

        if (roundTripped.length !== valid.length) {
            const missed = valid
                .filter((vector) => !roundTripped.includes(vector))
                .slice(0, 8)
                .map((vector) => `tcId ${vector.tcId}`)
                .join(', ');

            throw new Error(
                `recovery round trip: ${roundTripped.length}/${valid.length} valid signatures ` +
                    `produced a key that verifies in-circuit. Missed: ${missed}`,
            );
        }
    },
);

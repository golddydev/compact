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

import type { Contract, PureCircuits } from './.build/contract/index.js';
import { defineRuntimeTest } from '@test/compact-test';
import {
    assertBitcoinCoverage,
    classifyBitcoinVectors,
    isScalarRangeRejection,
    runWycheproofKat,
    type DrivenVector,
} from '@test/crypto';

// The full Bitcoin flow over the same corpus: SHA-256 in-circuit via
// `persistentHash`, then verify. Where ../ecdsa_verify isolates the curve
// arithmetic behind a pre-hashed digest, this drives hashing and verification
// together from the raw message -- so a divergence in either shows up.
//
// Routing is by message length, because `Bytes<N>` is fixed-size and SHA-256
// padding depends on the exact length. A length with no circuit is reported by
// name, so a corpus refresh that introduces one fails loudly instead of quietly
// covering less than it claims.
function drive(pure: PureCircuits, vector: DrivenVector): boolean {
    const name = `proveBitcoin${vector.msg.length}` as keyof PureCircuits;
    const circuit = pure[name] as
        | ((msg: Uint8Array, sig: unknown, pk: unknown) => boolean)
        | undefined;

    if (typeof circuit !== 'function') {
        throw new Error(
            `no ${name} circuit for tcId ${vector.tcId}; add a circuit for each ` +
                'message length in the corpus',
        );
    }

    try {
        return circuit(vector.msg, vector.sig, vector.pk);
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
        const byLength = new Map<number, number>();

        for (const vector of classifyBitcoinVectors().driven) {
            byLength.set(
                vector.msg.length,
                (byLength.get(vector.msg.length) ?? 0) + 1,
            );
        }

        const lengths = [...byLength.entries()]
            .sort(([a], [b]) => a - b)
            .map(([length, count]) => `${length}B=${count}`)
            .join(', ');

        assertBitcoinCoverage(
            runWycheproofKat(
                'secp256k1 Bitcoin flow (SHA-256 in-circuit + verify)',
                (vector) => drive(pure, vector),
                [`by msg length:         ${lengths}`],
            ),
        );
    },
);

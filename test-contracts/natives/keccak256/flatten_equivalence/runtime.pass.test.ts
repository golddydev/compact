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

import { bytesToHex } from '@noble/hashes/utils.js';
import { expect } from 'vitest';

import type { Contract, PureCircuits } from './.build/contract/index.js';
import { defineRuntimeTest } from '@test/compact-test';
import { runKat } from '@test/crypto';

// Types whose chunks concatenate to the same bytes must hash identically, so
// this needs no external oracle -- it compares the three circuits to each other.
//
// Every field contributes its FULL declared width, so the equivalence must hold
// for any byte pattern. Alongside the all-nonzero patterns, two zero-heavy
// inputs pin that: one with 0x00 at every field boundary (indices 0, 3, 4, 7, 11
// -- so `Uneven.head` is entirely zero and every `Triple` field ends in zero),
// and the all-zero value. Under a trailing-zero trim either would break the
// equivalence, which is what makes them worth including here rather than only in
// ../trailing_zero.
const inputs: Uint8Array[] = [
    Uint8Array.from({ length: 12 }, (_unused, i) => i + 1),
    Uint8Array.from({ length: 12 }, (_unused, i) => 0xf0 + i),
    new Uint8Array(12).fill(0xff),
    Uint8Array.from({ length: 12 }, (_unused, i) =>
        [0, 3, 4, 7, 11].includes(i) ? 0 : i + 1,
    ),
    new Uint8Array(12),
];

export default defineRuntimeTest<typeof Contract, PureCircuits>(
    import.meta.url,
    (_Contract, pure) => {
        runKat(
            'keccak256 flatten equivalence',
            inputs,
            (bytes) => `0x${bytesToHex(bytes)}`,
            (bytes) => {
                // The same 12 bytes, sliced along different field boundaries.
                const digests = {
                    'Bytes<12>': pure.hashBytes12(bytes),
                    Triple: pure.hashTriple({
                        a: bytes.slice(0, 4),
                        b: bytes.slice(4, 8),
                        c: bytes.slice(8, 12),
                    }),
                    Uneven: pure.hashUneven({
                        head: bytes.slice(0, 1),
                        mid: bytes.slice(1, 5),
                        tail: bytes.slice(5, 12),
                    }),
                };

                for (const [shape, digest] of Object.entries(digests)) {
                    expect(
                        digest,
                        `keccak256<${shape}> digest width`,
                    ).toHaveLength(32);
                }

                const reference = bytesToHex(digests['Bytes<12>']);

                for (const [shape, digest] of Object.entries(digests)) {
                    if (bytesToHex(digest) !== reference) {
                        throw new Error(
                            `keccak256<${shape}> = 0x${bytesToHex(digest)}, but ` +
                                `keccak256<Bytes<12>> = 0x${reference}; types that flatten ` +
                                'to the same bytes must hash equally',
                        );
                    }
                }
            },
        );
    },
);

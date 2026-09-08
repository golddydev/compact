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
import { loadAddressVectors, runKat, toHex } from '@test/crypto';

// The stdlib `secp256k1EthereumAddress` held to the canonical `ethereum/tests`
// key-to-address vectors. The circuit computes keccak256(x_be || y_be)[12:32),
// which IS the EIP derivation, so these must match exactly.
//
// The oracle is an external published fixture rather than a recomputation, so
// this is independent of the runtime's keccak implementation -- worth noting,
// because a keccak digest computed in JS would not be.
const vectors = loadAddressVectors();

export default defineRuntimeTest<typeof Contract, PureCircuits>(
    import.meta.url,
    (_Contract, pure) => {
        if (vectors.length === 0) {
            throw new Error('keyaddrtest.json produced no vectors');
        }

        runKat(
            'secp256k1EthereumAddress vs ethereum/tests',
            vectors,
            (vector) => `seed "${vector.seed}"`,
            ({ seed, point, ethAddr }) => {
                const address = pure.ethereumAddress(point);

                if (address.length !== 20) {
                    throw new Error(
                        `seed "${seed}": expected a 20-byte address, got ${address.length} bytes`,
                    );
                }

                const actual = `0x${toHex(address)}`;

                if (actual !== ethAddr) {
                    throw new Error(
                        `seed "${seed}": got ${actual}, expected ${ethAddr}`,
                    );
                }
            },
        );
    },
);

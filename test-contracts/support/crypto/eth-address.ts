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

import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import type { Secp256k1Point } from '@midnight-ntwrk/compact-runtime';
import { secp256k1 } from '@noble/curves/secp256k1.js';

/**
 * The canonical `ethereum/tests` key-to-address vectors vendored under `./data`.
 *
 * Each entry is `{ seed, key, addr, sig_of_emptystring }`, where `key` is the
 * 32-byte private scalar (`keccak256(seed)`, brain-wallet style) and `addr` is
 * the REAL Ethereum address, `keccak256(x_be ‖ y_be)[12:32)`.
 *
 * Note what the stdlib circuit actually computes:
 *
 *   `secp256k1EthereumAddress(pk) = slice<20>(keccak256<Secp256k1Point>(pk), 0)`
 *
 * That is keccak over the point's RUNTIME binary representation, taking the
 * FIRST 20 bytes — a different preimage and a different slice from the EIP
 * derivation above. The two do not agree, and a fixture holding the circuit to
 * `ethAddr` is documenting that divergence, not asserting a match.
 */

type KeyAddrEntry = {
    readonly seed: string;
    readonly key: string;
    readonly addr: string;
};

export type AddressVector = {
    readonly seed: string;
    /** Affine public key derived from the vector's private key. */
    readonly point: Secp256k1Point;
    /** The vector's real Ethereum address, `0x` + 40 lowercase hex. */
    readonly ethAddr: string;
};

export const ADDRESS_VECTORS_FILENAME = 'keyaddrtest.json';

const dataDir = path.join(path.dirname(fileURLToPath(import.meta.url)), 'data');

/** The affine public key for a 32-byte private scalar, given as hex. */
export function pubkeyPoint(privHex: string): Secp256k1Point {
    const { x, y } = secp256k1.Point.fromBytes(
        secp256k1.getPublicKey(hexToBytes(privHex), false),
    ).toAffine();

    return { x, y, identity: false };
}

/** Loads the vendored key-to-address vectors, deriving each public key point. */
export function loadAddressVectors(): AddressVector[] {
    const raw = JSON.parse(
        fs.readFileSync(path.join(dataDir, ADDRESS_VECTORS_FILENAME), 'utf8'),
    ) as KeyAddrEntry[];

    return raw.map((entry) => ({
        seed: entry.seed,
        point: pubkeyPoint(entry.key),
        ethAddr: `0x${entry.addr.toLowerCase()}`,
    }));
}

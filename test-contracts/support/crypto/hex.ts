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

/**
 * Hex conversion for crypto fixtures. Digests and test vectors are written as
 * lowercase hex so an assertion failure prints the whole value instead of a
 * `Uint8Array(32) [ 197, 210, ... ]` dump truncated by the reporter.
 */

/** Lowercase hex, no `0x` prefix, two characters per byte. */
export function toHex(bytes: Uint8Array): string {
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join(
        '',
    );
}

/** Parses lowercase or uppercase hex, with or without a leading `0x`. */
export function fromHex(hex: string): Uint8Array {
    const digits = hex.startsWith('0x') ? hex.slice(2) : hex;

    if (digits.length % 2 !== 0) {
        throw new Error(`odd-length hex string (${digits.length} digits)`);
    }

    const bytes = new Uint8Array(digits.length / 2);

    for (let i = 0; i < bytes.length; i++) {
        const byte = Number.parseInt(digits.slice(2 * i, 2 * i + 2), 16);

        if (Number.isNaN(byte)) {
            throw new Error(`invalid hex at byte ${i} of ${hex}`);
        }

        bytes[i] = byte;
    }

    return bytes;
}

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
 * Collect-then-report driver for known-answer tests.
 *
 * A crypto fixture drives a whole table through one Vitest test, so a plain
 * loop that throws on the first bad vector hides every vector behind it: with
 * 463 Wycheproof signatures or a 37-width digest sweep, "one failure" and "all
 * of them failed" have to look different in the output. `runKat` runs every
 * vector, then fails once with an aggregated message.
 */

export type KatOutcome = {
    /** Short vector identity, e.g. `Bytes<62>` or `tcId 388`. */
    label: string;
    ok: boolean;
    /** The failure message; absent when the vector passed. */
    detail?: string;
};

export type KatReport = {
    label: string;
    outcomes: KatOutcome[];
    passed: number;
    failed: KatOutcome[];
};

export type KatOptions = {
    /**
     * Extra lines appended to the summary, for coverage a fixture deliberately
     * did not drive (skipped encodings, carved malleability vectors). Keeping
     * them in the summary is what stops coverage being silently overstated.
     */
    notes?: string[];
    /** Failing vectors named in the thrown message before it elides the rest. */
    sampleSize?: number;
};

/**
 * Runs `check` over every vector. A vector passes when `check` returns without
 * throwing; the thrown error's message becomes its failure detail.
 *
 * Throws once, at the end, if any vector failed.
 */
export function runKat<V>(
    label: string,
    vectors: readonly V[],
    labelOf: (vector: V) => string,
    check: (vector: V) => void,
    options: KatOptions = {},
): KatReport {
    const outcomes: KatOutcome[] = [];

    for (const vector of vectors) {
        const vectorLabel = labelOf(vector);

        try {
            check(vector);
            outcomes.push({ label: vectorLabel, ok: true });
        } catch (error) {
            outcomes.push({
                label: vectorLabel,
                ok: false,
                detail: error instanceof Error ? error.message : String(error),
            });
        }
    }

    const report = buildReport(label, outcomes);

    if (report.failed.length > 0) {
        throw new Error(formatFailure(report, options));
    }

    return report;
}

/**
 * Groups outcomes into a report. Exposed for fixtures that drive their vectors
 * themselves — the Wycheproof suite classifies failures further before it can
 * decide whether one is a finding — and still want the shared summary shape.
 */
export function buildReport(label: string, outcomes: KatOutcome[]): KatReport {
    const failed = outcomes.filter((outcome) => !outcome.ok);

    return {
        label,
        outcomes,
        passed: outcomes.length - failed.length,
        failed,
    };
}

/**
 * Renders a report as the message of the single error a failed KAT throws.
 */
export function formatFailure(
    report: KatReport,
    options: KatOptions = {},
): string {
    const { notes = [], sampleSize = 8 } = options;
    const { label, outcomes, passed, failed } = report;
    const sample = failed
        .slice(0, sampleSize)
        .map((outcome) => `${outcome.label}: ${outcome.detail}`);
    const elided = failed.length - sample.length;

    return [
        `${label}: ${failed.length}/${outcomes.length} vectors failed (${passed} passed).`,
        ...notes.map((note) => `  ${note}`),
        ...sample.map((line) => `  ${line}`),
        ...(elided > 0 ? [`  ...and ${elided} more`] : []),
    ].join('\n');
}

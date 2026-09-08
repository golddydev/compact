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

import { defineCompileTest } from '@test/compact-test';

// Compiled WITH the v3 flag so the ADT type error is what fails. Without it the
// zkir-v2 keccak256 gate fires first and the fixture would pass for the wrong
// reason -- the diagnostic below is matched precisely for that reason.
export default defineCompileTest(import.meta.url, {
    compilerArgs: ['--feature-zkir-v3'],
    expectedError:
        /expected argument 'value' type to be an ordinary Compact type but received ADT type Counter/,
});

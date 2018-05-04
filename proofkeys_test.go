/*
 * BSD 3-Clause License
 *
 * Copyright (c) 2018, Virgil Security, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 *  Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 *  Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package pythia

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewProofKeys(t *testing.T) {
	keys, err := NewProofKeys(
		"PK.5.AgTn2njhhYeI94f/Ci20djo7+MgtfMt18ZjMjBAG3DYhzljZlugXWHkMucOWn20MLA==",
		"PK.1.AgTn2njhhYeI94f/Ci20djo7+MgtfMt18ZjMjBAG3DYhzljZlugXWHkMucOWn20MLA==",
		"PK.2.AgwhFXaYR7EWiTxeCCj269+cZKcRiT7x2Ifbyi4HrMnpSCapaoUzoK8rIJSNJC++jA==",
		"PK.4.AgTn2njhhYeI94f/Ci20djo7+MgtfMt18ZjMjBAG3DYhzljZlugXWHkMucOWn20MLA==")
	assert.NoError(t, err)

	current, err := keys.GetCurrent()

	assert.NoError(t, err)

	assert.Equal(t, uint(5), current.Version)

	k2, err := keys.Get(2)
	assert.NoError(t, err)
	assert.Equal(t, k2, []uint8([]byte{0x2, 0xc, 0x21, 0x15, 0x76, 0x98, 0x47, 0xb1, 0x16, 0x89, 0x3c, 0x5e, 0x8, 0x28, 0xf6, 0xeb, 0xdf, 0x9c, 0x64, 0xa7, 0x11, 0x89, 0x3e, 0xf1, 0xd8, 0x87, 0xdb, 0xca, 0x2e, 0x7, 0xac, 0xc9, 0xe9, 0x48, 0x26, 0xa9, 0x6a, 0x85, 0x33, 0xa0, 0xaf, 0x2b, 0x20, 0x94, 0x8d, 0x24, 0x2f, 0xbe, 0x8c}))

	_, err = keys.Get(3)
	assert.Error(t, err)

	keys, err = NewProofKeys("P.5.AgwhFXaYR7")
	assert.Error(t, err)
	assert.Nil(t, keys)

}

// +build integration

/*
 * BSD 3-Clause License
 *
 * Copyright (c) 2015-2018, Virgil Security, Inc.
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
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestThrottle(t *testing.T) {

	pythia1, err := initTestContext("PROOF_KEYS_2")

	assert.NoError(t, err)

	var bpp *BreachProofPassword

	for i := 0; i < 2; i++ {
		bpp, err = pythia1.CreateBreachProofPassword("some password")
		assert.NoError(t, err)
		bpp2, err := pythia1.CreateBreachProofPassword("some password")
		assert.NoError(t, err)
		assert.NotEqual(t, bpp.Salt, bpp2.Salt)
		assert.NotEqual(t, bpp.DeblindedPassword, bpp2.DeblindedPassword)
		assert.Equal(t, bpp.Version, bpp2.Version)
	}

	err = pythia1.VerifyBreachProofPassword("some password", bpp, false)
	assert.Error(t, err)
}

func initTestContext(proofKeysArgName string) (*Protocol, error) {
	apiUrl := os.Getenv("TEST_ADDRESS")
	apiKey := os.Getenv("TEST_API_KEY")
	apikeyId := os.Getenv("TEST_API_KEY_ID")
	appId := os.Getenv("TEST_APP_ID")
	proofKeysArg := os.Getenv(proofKeysArgName)

	proofKeys := strings.Split(proofKeysArg, ",")

	if apiKey == "" || apikeyId == "" || appId == "" || os.Getenv("UPDATE_TOKEN") == "" {
		return nil, errors.New("all args are mandatory")
	}

	ctx, err := CreateContext(apiKey, apikeyId, appId, proofKeys...)
	if err != nil {
		return nil, err
	}
	ctx.Client.ServiceURL = apiUrl

	if err != nil {
		return nil, err
	}

	pythia := New(ctx)
	return pythia, nil
}

func TestUpdate1(t *testing.T) {

	pythia1, err := initTestContext("PROOF_KEYS_1")

	assert.NoError(t, err)

	bpp1, err := pythia1.CreateBreachProofPassword("some password")
	assert.NoError(t, err)

	assert.Equal(t, uint(2), bpp1.Version)

	pythia2, err := initTestContext("PROOF_KEYS_2")

	bpp2, err := pythia2.UpdateBreachProofPassword(os.Getenv("UPDATE_TOKEN"), bpp1)

	assert.Equal(t, bpp2.Salt, bpp1.Salt)
	assert.NotEqual(t, bpp2.DeblindedPassword, bpp1.DeblindedPassword)
	assert.Equal(t, uint(3), bpp2.Version)

	time.Sleep(time.Second * 2)
	err = pythia2.VerifyBreachProofPassword("some password", bpp1, false)
	assert.NoError(t, err)
	time.Sleep(time.Second * 2)
	err = pythia2.VerifyBreachProofPassword("some password", bpp2, false)
	assert.NoError(t, err)

}

func TestUpdate2(t *testing.T) {

	pythia1, err := initTestContext("PROOF_KEYS_2")

	assert.NoError(t, err)

	bpp1, err := pythia1.CreateBreachProofPassword("some password")
	assert.NoError(t, err)

	bpp2, err := pythia1.UpdateBreachProofPassword(os.Getenv("UPDATE_TOKEN"), bpp1)

	assert.Nil(t, bpp2)
	assert.Error(t, err)

}

func TestUpdate3(t *testing.T) {

	pythia1, err := initTestContext("PROOF_KEYS_3")

	assert.NoError(t, err)

	bpp1, err := pythia1.CreateBreachProofPassword("some password")
	assert.Error(t, err)

	bpp2, err := pythia1.UpdateBreachProofPassword(os.Getenv("UPDATE_TOKEN"), bpp1)

	assert.Nil(t, bpp2)
	assert.Error(t, err)

}

func TestUpdate4(t *testing.T) {

	pythia1, err := initTestContext("PROOF_KEYS_1")

	assert.NoError(t, err)

	bpp1, err := pythia1.CreateBreachProofPassword("some password")
	assert.NoError(t, err)

	bpp2, err := pythia1.UpdateBreachProofPassword("PK.2.3.AGnR4LLnbBIDoPxy3OftLiw4tqRYd0NtRlvsM4dH0hlT", bpp1)

	assert.Nil(t, bpp2)
	assert.Error(t, err)

}

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
	"time"

	"github.com/pkg/errors"
	"gopkg.in/virgil.v5/sdk"
	"gopkg.in/virgilsecurity/virgil-crypto-go.v5"
	"gopkg.in/virgilsecurity/virgil-crypto-go.v5/pythia"
)

type Context struct {
	Provider  sdk.AccessTokenProvider
	Client    *Client
	Crypto    *pythia.Pythia
	ProofKeys ProofKeys
}

func CreateContext(apiKey, apiKeyID, appID string, proofKeys ...string) (*Context, error) {

	if apiKey == "" || apiKeyID == "" || appID == "" || len(proofKeys) == 0 {
		return nil, errors.New("all parameters are mandatory")
	}

	keys, err := NewProofKeys(proofKeys...)
	if err != nil {
		return nil, err
	}

	client := NewClient("")

	pythiaCrypto := pythia.New()
	crypto := virgil_crypto_go.NewVirgilCrypto()

	apiPrivateKey, err := crypto.ImportPrivateKey([]byte(apiKey), "")

	if err != nil {
		return nil, err
	}

	generator := sdk.NewJwtGenerator(apiPrivateKey, apiKeyID, virgil_crypto_go.NewVirgilAccessTokenSigner(), appID, time.Hour)
	accessTokenProvider := sdk.NewCachingJwtProvider(func(context *sdk.TokenContext) (*sdk.Jwt, error) {
		jwt, err := generator.GenerateToken("PYTHIA-CLIENT", nil)
		if err != nil {
			return nil, err
		}
		return jwt, nil
	})

	return &Context{
		ProofKeys: keys,
		Client:    client,
		Crypto:    pythiaCrypto,
		Provider:  accessTokenProvider,
	}, nil
}

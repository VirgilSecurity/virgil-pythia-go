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
	"sync"

	"gopkg.in/virgil.v5/cryptoapi"
	"gopkg.in/virgil.v5/errors"
	"gopkg.in/virgil.v5/sdk"
	"gopkg.in/virgilsecurity/virgil-crypto-go.v5"
	"gopkg.in/virgilsecurity/virgil-crypto-go.v5/pythia"
)

type BrainKey struct {
	AccessTokenProvider sdk.AccessTokenProvider
	Client              *Client
	Crypto              *pythia.Pythia
	KeypairType         virgil_crypto_go.KeyType
	onceClient          sync.Once
}

func NewBrainKey(params *BrainKeyContext) *BrainKey {

	return &BrainKey{
		AccessTokenProvider: params.Provider,
		Client:              params.Client,
		Crypto:              params.Pythia,
		KeypairType:         params.KeypairType,
	}
}

func (b *BrainKey) GenerateKeypair(password string, brainKeyId string) (keypair cryptoapi.Keypair, err error) {
	if err := b.selfCheck(); err != nil {
		return nil, err
	}

	tokenContext := &sdk.TokenContext{Identity: "", Operation: "seed", Service: "Pythia"}
	token, err := b.AccessTokenProvider.GetToken(tokenContext)
	if err != nil {
		return nil, err
	}

	blindedPassword, secret, err := b.Crypto.Blind([]byte(password))
	if err != nil {
		return nil, err
	}

	protected, err := b.getClient().GenerateSeed(blindedPassword, brainKeyId, token.String())

	if err != nil {
		return nil, err
	}

	seed, err := b.Crypto.Deblind(protected, secret)

	if err != nil {
		return nil, err
	}

	keypair, err = b.Crypto.GenerateKeypair(b.KeypairType, seed)

	return
}

func (b *BrainKey) getClient() *Client {
	b.onceClient.Do(func() {
		if b.Client == nil {
			b.Client = &Client{}
		}
	})

	return b.Client
}

func (b *BrainKey) selfCheck() error {
	if b.Crypto == nil {
		return errors.New("Crypto must be set")
	}

	if b.AccessTokenProvider == nil {
		return errors.New("AccessTokenProvider must be set")
	}
	return nil
}

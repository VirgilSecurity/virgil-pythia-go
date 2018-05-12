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

	"crypto/subtle"

	"crypto/rand"

	"encoding/base64"

	"strconv"
	"strings"

	"gopkg.in/virgil.v5/errors"
	"gopkg.in/virgil.v5/sdk"
	"gopkg.in/virgilsecurity/virgil-crypto-go.v5/pythia"
)

type Protocol struct {
	AccessTokenProvider sdk.AccessTokenProvider
	Client              *Client
	ProofKeys           ProofKeys
	Pythia              *pythia.Pythia
	onceClient          sync.Once
}

func New(params *Context) *Protocol {

	return &Protocol{
		AccessTokenProvider: params.Provider,
		Client:              params.Client,
		ProofKeys:           params.ProofKeys,
		Pythia:              params.Crypto,
	}
}

func (p *Protocol) VerifyBreachProofPassword(password string, pwd *BreachProofPassword, prove bool) (err error) {
	if err := p.selfCheck(); err != nil {
		return err
	}

	if err := p.pwdCheck(pwd); err != nil {
		return err
	}
	tokenContext := &sdk.TokenContext{Identity: "", Operation: "verify", Service: "Pythia"}
	token, err := p.AccessTokenProvider.GetToken(tokenContext)
	if err != nil {
		return err
	}

	blindedPassword, secret, err := p.Pythia.Blind([]byte(password))
	if err != nil {
		return err
	}

	protected, err := p.getClient().ProtectPassword(pwd.Salt, blindedPassword, pwd.Version, prove, token.String())

	if err != nil {
		return err
	}

	if prove {

		if err := p.verify(protected, pwd.Version, blindedPassword, pwd.Salt); err != nil {
			return err
		}

	}

	deblinded, err := p.Pythia.Deblind(protected.TransformedPassword, secret)

	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(deblinded, pwd.DeblindedPassword) != 1 {
		return errors.New("authentication failed")
	}

	return nil
}

func (p *Protocol) CreateBreachProofPassword(password string) (*BreachProofPassword, error) {
	if err := p.selfCheck(); err != nil {
		return nil, err
	}

	salt := make([]byte, 32)
	rand.Read(salt)

	tokenContext := &sdk.TokenContext{Identity: "", Operation: "register", Service: "Pythia"}
	token, err := p.AccessTokenProvider.GetToken(tokenContext)
	if err != nil {
		return nil, err
	}

	blindedPassword, secret, err := p.Pythia.Blind([]byte(password))
	if err != nil {
		return nil, err
	}

	proofKey, err := p.ProofKeys.GetCurrent()
	if err != nil {
		return nil, err
	}

	protected, err := p.getClient().ProtectPassword(salt, blindedPassword, proofKey.Version, true, token.String())
	if err != nil {
		return nil, err
	}

	if err := p.verify(protected, proofKey.Version, blindedPassword, salt); err != nil {
		return nil, err
	}

	deblinded, err := p.Pythia.Deblind(protected.TransformedPassword, secret)

	if err != nil {
		return nil, err
	}

	return &BreachProofPassword{
		Salt:              salt,
		Version:           proofKey.Version,
		DeblindedPassword: deblinded,
	}, nil
}

func (p *Protocol) UpdateBreachProofPassword(updateToken string, pwd *BreachProofPassword) (*BreachProofPassword, error) {

	if err := p.selfCheck(); err != nil {
		return nil, err
	}

	oldVersion, newVersion, token, err := parseToken(updateToken)
	if err != nil {
		return nil, err
	}

	if pwd.Version == newVersion {
		return nil, errors.New("this user has already been updated")
	}

	if pwd.Version != oldVersion {
		return nil, errors.New("password's version does not match this update token")
	}

	if err = p.pwdCheck(pwd); err != nil {
		return nil, err
	}

	if err != nil {
		return nil, err
	}

	newDeblinded, err := p.Pythia.UpdateDeblindedWithToken(pwd.DeblindedPassword, token)
	if err != nil {
		return nil, err
	}

	newSalt := make([]byte, len(pwd.Salt))
	copy(newSalt, pwd.Salt)

	return &BreachProofPassword{
		DeblindedPassword: newDeblinded,
		Version:           newVersion,
		Salt:              newSalt,
	}, nil
}

func parseToken(s string) (oldVersion uint, newVersion uint, token []byte, err error) {
	if s == "" {
		err = errors.New("key is empty")
		return
	}

	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		err = errors.New("incorrect update token format")
		return
	}

	if parts[0] != "UT" {
		err = errors.New("incorrect update token format")
		return
	}

	tmp, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		err = errors.New("incorrect update token format")
		return
	}

	oldVersion = uint(tmp)

	tmp, err = strconv.ParseUint(parts[2], 10, 32)
	if err != nil {
		err = errors.New("incorrect update token format")
		return
	}

	newVersion = uint(tmp)

	if len(parts[3]) < 32 || len(parts[3]) > 70 {
		err = errors.New("incorrect update token format")
		return
	}

	token, err = base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		err = errors.New("incorrect update token format")
		return
	}
	return
}

func (p *Protocol) verify(protected *PasswordResp, version uint, blindedPassword, salt []byte) error {
	if protected.Proof == nil || protected.Proof.ValueC == nil || protected.Proof.ValueU == nil {
		return errors.New("proof requested but was not received")
	}

	if p.ProofKeys == nil {
		return errors.New("proof requested but ProofKeys is not set")
	}

	proofKey, err := p.ProofKeys.Get(version)
	if err != nil {
		return err
	}

	err = p.Pythia.Verify(protected.TransformedPassword, blindedPassword, salt, proofKey, protected.Proof.ValueC, protected.Proof.ValueU)
	if err != nil {
		return errors.New("value verification failed")
	}
	return nil
}

func (c *Protocol) getClient() *Client {
	c.onceClient.Do(func() {
		if c.Client == nil {
			c.Client = &Client{}
		}
	})

	return c.Client
}

func (p *Protocol) pwdCheck(pwd *BreachProofPassword) error {
	if pwd == nil {
		return errors.New("pwd is nil")
	}
	if len(pwd.Salt) == 0 || len(pwd.DeblindedPassword) == 0 {
		return errors.New("pwd object does not have salt or deblindedPassword set")
	}
	return nil
}

func (p *Protocol) selfCheck() error {
	if p.Pythia == nil {
		return errors.New("Pythia must be set")
	}

	if p.AccessTokenProvider == nil {
		return errors.New("AccessTokenProvider must be set")
	}
	return nil
}

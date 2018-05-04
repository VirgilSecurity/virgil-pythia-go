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
	"encoding/base64"
	"strconv"
	"strings"

	"sort"

	"github.com/pkg/errors"
)

type ProofKey struct {
	Key     []byte
	Version uint
}

type ProofKeys []*ProofKey

func NewProofKeys(proofKeys ...string) (ProofKeys, error) {

	if len(proofKeys) == 0 {
		return nil, errors.New("no proof keys provided")
	}

	var keys ProofKeys

	for _, pk := range proofKeys {
		if pk == "" {
			return nil, errors.New("proof key is empty")
		}
		version, key, err := parseProofKey(pk)
		if err != nil {
			return nil, err
		}

		keys = append(keys, &ProofKey{
			Version: version,
			Key:     key,
		})
	}

	//reverse sort
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].Version > keys[j].Version
	})

	return keys, nil
}

func parseProofKey(pk string) (version uint, key []byte, err error) {
	if pk == "" {
		err = errors.New("proof key is empty")
		return
	}

	parts := strings.Split(pk, ".")
	if len(parts) != 3 {
		err = errors.New("incorrect proof key format")
		return
	}

	if parts[0] != "PK" {
		err = errors.New("incorrect proof key format")
		return
	}

	tmp, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return
	}

	version = uint(tmp)

	if len(parts[2]) < 32 || len(parts[2]) > 70 {
		err = errors.New("incorrect proof key format")
		return
	}

	key, err = base64.StdEncoding.DecodeString(parts[2])
	return
}

func (t ProofKeys) Get(version uint) ([]byte, error) {

	i := sort.Search(len(t), func(i int) bool {
		return t[i].Version <= version
	})

	if i >= len(t) || t[i].Version != version {
		return nil, errors.New("proof key with such version not found")
	}

	return t[i].Key, nil
}

func (t ProofKeys) GetCurrent() (*ProofKey, error) {

	if len(t) == 0 {
		return nil, errors.New("no proof keys")
	}

	if t[0] == nil || len(t[0].Key) == 0 {
		return nil, errors.New("current proof key is invalid")
	}

	return t[0], nil
}

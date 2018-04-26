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

	for _, pk := range t {
		if pk.Version == version {
			return pk.Key, nil
		}
	}
	return nil, errors.New("proof key with such version not found")
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

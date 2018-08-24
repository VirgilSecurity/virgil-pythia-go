package sdk

import "gopkg.in/virgil.v4/virgilcrypto"

type AccessTokenSigner interface {
	GenerateTokenSignature(data []byte, privateKey virgilcrypto.PrivateKey) ([]byte, error)
	GetAlgorithm() string
}

package pythia

import (
	"time"

	"gopkg.in/virgil.v5/cryptoapi"
	"gopkg.in/virgil.v5/sdk"
	"gopkg.in/virgilsecurity/virgil-crypto-go.v5"
)

type Params struct {
	proofKeys           ProofKeys
	AccessTokenProvider sdk.AccessTokenProvider
	Client              *Client
}

func MakeParams(apiKey cryptoapi.PrivateKey, apiKeyId, appId string, proofKeys ...string) (*Params, error) {
	client := NewClient("")
	generator := sdk.NewJwtGenerator(apiKey, apiKeyId, virgil_crypto_go.NewVirgilAccessTokenSigner(), appId, time.Hour)

	accessTokenProvider := sdk.NewCachingJwtProvider(func(context *sdk.TokenContext) (string, error) {
		jwt, err := generator.GenerateToken("pythia", nil)
		if err != nil {
			return "", nil
		}
		return jwt.String(), nil
	})

	keys, err := NewProofKeys(proofKeys...)
	if err != nil {
		return nil, err
	}

	return &Params{
		proofKeys:           keys,
		Client:              client,
		AccessTokenProvider: accessTokenProvider,
	}, nil
}

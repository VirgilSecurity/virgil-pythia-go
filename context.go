package pythia

import (
	"time"

	"github.com/VirgilSecurity/pythia-lib-go"
	"github.com/pkg/errors"
	"gopkg.in/virgil.v5/sdk"
	"gopkg.in/virgilsecurity/virgil-crypto-go.v5"
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

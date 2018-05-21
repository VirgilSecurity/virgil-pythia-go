package pythia

import (
	"os"

	"time"

	"encoding/hex"
	"fmt"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"gopkg.in/virgil.v5/sdk"
	"gopkg.in/virgilsecurity/virgil-crypto-go.v5"
)

func initTestBrainkeyContext(identity string) (*BrainKey, error) {
	apiUrl := os.Getenv("TEST_ADDRESS")
	apiKey := os.Getenv("TEST_API_KEY")
	apikeyId := os.Getenv("TEST_API_KEY_ID")
	appId := os.Getenv("TEST_APP_ID")

	if apiKey == "" || apikeyId == "" || appId == "" {
		return nil, errors.New("all args are mandatory")
	}

	crypto := virgil_crypto_go.NewVirgilCrypto()

	apiPrivateKey, err := crypto.ImportPrivateKey([]byte(apiKey), "")

	if err != nil {
		return nil, err
	}

	generator := sdk.NewJwtGenerator(apiPrivateKey, apikeyId, virgil_crypto_go.NewVirgilAccessTokenSigner(), appId, time.Hour)
	accessTokenProvider := sdk.NewCachingJwtProvider(func(context *sdk.TokenContext) (*sdk.Jwt, error) {
		jwt, err := generator.GenerateToken(identity, nil)
		if err != nil {
			return nil, err
		}
		return jwt, nil
	})

	ctx, err := CreateBrainKeyContext(accessTokenProvider)
	if err != nil {
		return nil, err
	}
	ctx.Client.ServiceURL = apiUrl

	if err != nil {
		return nil, err
	}

	brainkey := NewBrainKey(ctx)
	return brainkey, nil
}

func TestBrainKey_GenerateKeypair(t *testing.T) {
	brainKey, err := initTestBrainkeyContext("Alice")

	assert.NoError(t, err)
	kp, err := brainKey.GenerateKeypair("password", "mainKey")
	assert.NoError(t, err)

	crypto := virgil_crypto_go.NewVirgilCrypto()

	sk, err := crypto.ExportPrivateKey(kp.PrivateKey(), "")
	assert.NoError(t, err)
	pk, err := crypto.ExportPublicKey(kp.PublicKey())
	assert.NoError(t, err)
	fmt.Println(hex.EncodeToString(sk))
	fmt.Println(hex.EncodeToString(pk))

}

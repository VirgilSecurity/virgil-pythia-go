package pythia

import (
	"sync"
	"time"

	"crypto/subtle"

	"crypto/rand"

	"github.com/VirgilSecurity/pythia-lib-go"
	"gopkg.in/virgil.v5/errors"
	"gopkg.in/virgil.v5/sdk"
	"gopkg.in/virgilsecurity/virgil-crypto-go.v5"
)

type Protocol struct {
	AccessTokenProvider         sdk.AccessTokenProvider
	Client                      *Client
	onceClient, onceCheckParams sync.Once
	ProofKeys                   ProofKeys
	Crypto                      *pythia.Pythia
	paramsError                 error
}

func New(params *Params) (*Protocol, error) {

	client := NewClient("")

	pythiaCrypto := pythia.New()
	crypto := virgil_crypto_go.NewVirgilCrypto()

	apiKey, err := crypto.ImportPrivateKey([]byte(params.ApiKey), "")

	if err != nil {
		return nil, err
	}

	generator := sdk.NewJwtGenerator(apiKey, params.ApiKeyID, virgil_crypto_go.NewVirgilAccessTokenSigner(), params.AppID, time.Hour)

	accessTokenProvider := sdk.NewCachingJwtProvider(func(context *sdk.TokenContext) (string, error) {
		jwt, err := generator.GenerateToken("pythia", nil)
		if err != nil {
			return "", nil
		}
		return jwt.String(), nil
	})

	return &Protocol{
		AccessTokenProvider: accessTokenProvider,
		Client:              client,
		ProofKeys:           params.proofKeys,
		Crypto:              pythiaCrypto,
	}, nil
}

func (p *Protocol) Authenticate(password string, user *User, prove bool) (err error) {
	if err := p.selfCheck(); err != nil {
		return err
	}

	if err := p.userCheck(user); err != nil {
		return err
	}
	tokenContext := &sdk.TokenContext{Identity: "", Operation: "protect"}
	token, err := p.AccessTokenProvider.GetToken(tokenContext)
	if err != nil {
		return err
	}

	blindedPassword, secret, err := p.Crypto.Blind([]byte(password))
	if err != nil {
		return err
	}

	protected, err := p.getClient().ProtectPassword(user.Salt, blindedPassword, user.version, prove, token.String())

	if err != nil {
		return err
	}

	if prove {

		if err := p.verify(protected, user.version, blindedPassword, user.Salt); err != nil {
			return err
		}

	}

	deblinded, err := p.Crypto.Deblind(protected.TransformedPassword, secret)

	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(deblinded, user.DeblindedPassword) != 1 {
		return errors.New("authentication failed")
	}

	return nil
}

func (p *Protocol) Register(password string) (*User, error) {
	if err := p.selfCheck(); err != nil {
		return nil, err
	}

	salt := make([]byte, 32)
	rand.Read(salt)

	tokenContext := &sdk.TokenContext{Identity: "", Operation: "protect"}
	token, err := p.AccessTokenProvider.GetToken(tokenContext)
	if err != nil {
		return nil, err
	}

	blindedPassword, secret, err := p.Crypto.Blind([]byte(password))
	if err != nil {
		return nil, err
	}

	proofKey, err := p.ProofKeys.GetCurrent()
	if err != nil {
		return nil, err
	}

	protected, err := p.getClient().ProtectPassword(salt, blindedPassword, proofKey.Version, true, token.String())

	if err := p.verify(protected, proofKey.Version, blindedPassword, salt); err != nil {
		return nil, err
	}

	deblinded, err := p.Crypto.Deblind(protected.TransformedPassword, secret)

	if err != nil {
		return nil, err
	}

	return &User{
		Salt:              salt,
		version:           proofKey.Version,
		DeblindedPassword: deblinded,
	}, nil
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

	err = p.Crypto.Verify(protected.TransformedPassword, blindedPassword, salt, proofKey, protected.Proof.ValueC, protected.Proof.ValueU)
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

func (p *Protocol) userCheck(user *User) error {
	if user == nil {
		return errors.New("user is nil")
	}
	if len(user.Salt) == 0 || len(user.DeblindedPassword) == 0 {
		return errors.New("user object does not have salt or deblindedPassword set")
	}
	return nil
}

func (c *Protocol) selfCheck() error {
	c.onceCheckParams.Do(func() {
		if c.Crypto == nil {
			c.paramsError = errors.New("Crypto must be set")
			return
		}

		if c.AccessTokenProvider == nil {
			c.paramsError = errors.New("AccessTokenProvider must be set")
			return
		}

	})
	return c.paramsError
}

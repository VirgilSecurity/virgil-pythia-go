package pythia

import (
	"sync"

	"crypto/subtle"

	"crypto/rand"

	"encoding/base64"

	"github.com/VirgilSecurity/pythia-lib-go"
	"gopkg.in/virgil.v5/errors"
	"gopkg.in/virgil.v5/sdk"
)

type Protocol struct {
	AccessTokenProvider sdk.AccessTokenProvider
	Client              *Client
	ProofKeys           ProofKeys
	Crypto              *pythia.Pythia
	onceClient          sync.Once
}

func New(params *Context) *Protocol {

	return &Protocol{
		AccessTokenProvider: params.Provider,
		Client:              params.Client,
		ProofKeys:           params.ProofKeys,
		Crypto:              params.Crypto,
	}
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

	protected, err := p.getClient().ProtectPassword(user.Salt, blindedPassword, user.Version, prove, token.String())

	if err != nil {
		return err
	}

	if prove {

		if err := p.verify(protected, user.Version, blindedPassword, user.Salt); err != nil {
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
		Version:           proofKey.Version,
		DeblindedPassword: deblinded,
	}, nil
}

func (p *Protocol) UpdateUser(updateToken string, user *User) (*User, error) {

	if err := p.selfCheck(); err != nil {
		return nil, err
	}

	token, err := base64.StdEncoding.DecodeString(updateToken)
	if err != nil {
		return nil, err
	}

	if len(token) < 10 || len(token) > 32 {
		return nil, errors.New("invalid update token")
	}

	if err = p.userCheck(user); err != nil {
		return nil, err
	}

	if p.ProofKeys == nil {
		return nil, errors.New("proof requested but ProofKeys is not set")
	}

	currentProofKey, err := p.ProofKeys.GetCurrent()

	if err != nil {
		return nil, err
	}

	newDeblinded, err := p.Crypto.UpdateDeblindedWithToken(user.DeblindedPassword, token)
	if err != nil {
		return nil, err
	}

	return &User{
		DeblindedPassword: newDeblinded,
		Version:           currentProofKey.Version,
		Salt:              user.Salt,
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

func (p *Protocol) selfCheck() error {
	if p.Crypto == nil {
		return errors.New("Crypto must be set")
	}

	if p.AccessTokenProvider == nil {
		return errors.New("AccessTokenProvider must be set")
	}
	return nil
}

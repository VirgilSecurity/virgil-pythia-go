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

func (p *Protocol) VerifyBreachProofPassword(password string, pwd *BreachProofPassword, prove bool) (err error) {
	if err := p.selfCheck(); err != nil {
		return err
	}

	if err := p.pwdCheck(pwd); err != nil {
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

	protected, err := p.getClient().ProtectPassword(pwd.Salt, blindedPassword, pwd.Version, prove, token.String())

	if err != nil {
		return err
	}

	if prove {

		if err := p.verify(protected, pwd.Version, blindedPassword, pwd.Salt); err != nil {
			return err
		}

	}

	deblinded, err := p.Crypto.Deblind(protected.TransformedPassword, secret)

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

	tokenContext := &sdk.TokenContext{Identity: "", Operation: "protect", Service: "Pythia"}
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
	if err != nil {
		return nil, err
	}

	if err := p.verify(protected, proofKey.Version, blindedPassword, salt); err != nil {
		return nil, err
	}

	deblinded, err := p.Crypto.Deblind(protected.TransformedPassword, secret)

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
		return nil, errors.New("this pwd has already been updated")
	}

	if pwd.Version != oldVersion {
		return nil, errors.New("pwd's version does not match this update token")
	}

	if err = p.pwdCheck(pwd); err != nil {
		return nil, err
	}

	if err != nil {
		return nil, err
	}

	newDeblinded, err := p.Crypto.UpdateDeblindedWithToken(pwd.DeblindedPassword, token)
	if err != nil {
		return nil, err
	}

	return &BreachProofPassword{
		DeblindedPassword: newDeblinded,
		Version:           newVersion,
		Salt:              pwd.Salt,
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

	token, err = base64.StdEncoding.DecodeString(parts[2])
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
	if p.Crypto == nil {
		return errors.New("Crypto must be set")
	}

	if p.AccessTokenProvider == nil {
		return errors.New("AccessTokenProvider must be set")
	}
	return nil
}

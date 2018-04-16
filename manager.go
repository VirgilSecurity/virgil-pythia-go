package pythia

import (
	"sync"

	"gopkg.in/virgil.v5/errors"
	"gopkg.in/virgil.v5/sdk"
	"gopkg.in/virgilsecurity/virgil-crypto-go.v5"
)

type Manager struct {
	AccessTokenProvider         sdk.AccessTokenProvider
	PythiaClient                *PythiaClient
	onceClient, onceCheckParams sync.Once
	Crypto                      *virgil_crypto_go.ExternalCrypto
	paramsError                 error
}

func (m *Manager) ProtectPassword(userID, password string, version int, validationPublicKey []byte) (protectedPassword []byte, err error) {
	if err := m.selfCheck(); err != nil {
		return nil, err
	}
	tokenContext := &sdk.TokenContext{Identity: userID, Operation: "protect"}
	token, err := m.AccessTokenProvider.GetToken(tokenContext)
	if err != nil {
		return nil, err
	}

	needProof := validationPublicKey != nil

	blindedPassword, secret, err := m.Pythia.Blind([]byte(password))

	protected, err := m.getClient().ProtectPassword(blindedPassword, needProof, version, token.String())

	if needProof{

		if protected.Proof == nil || protected.Proof.ValueC == nil || protected.Proof.ValueU == nil{
			return nil, errors.New("Proof requested but was not received")
		}

		err = m.Pythia.Verify(blindedPassword, protected.TransformedPassword, validationPublicKey, protected.Proof.ValueC, protected.Proof.ValueU
		if err != nil{
			return nil, errors.New("value verification failed")
		}
	}

	deblinded, err := m.Pythia.Deblind(protected.TransformedPassword)

	if err != nil {
		return nil, err
	}
	return deblinded, nil
}

func (c *Manager) getClient() *PythiaClient {
	c.onceClient.Do(func() {
		if c.PythiaClient == nil {
			c.PythiaClient = &PythiaClient{}
		}
	})

	return c.PythiaClient
}

func (c *Manager) selfCheck() error {
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

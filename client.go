package pythia

import (
	"net/http"
	"sync"

	"gopkg.in/virgil.v5/common"
	"gopkg.in/virgil.v5/errors"
)

type PythiaClient struct {
	ServiceURL       string
	VirgilHttpClient *common.VirgilHttpClient
	HttpClient       common.HttpClient
	once             sync.Once
}

func NewPythiaClient(serviceURL string) *PythiaClient {
	return &PythiaClient{ServiceURL: serviceURL}
}

func (c *PythiaClient) ProtectPassword(blindedPassword []byte, includeProof bool, version int, token string) (*PasswordResp, error) {

	req := &PasswordReq{
		BlindedPassword: blindedPassword,
		IncludeProof:    includeProof,
		Version:         version,
	}

	var resp *PasswordResp
	_, err := c.send(http.MethodPost, "/password", token, req, &resp)

	return resp, err
}

func (c *PythiaClient) send(method string, url string, token string, payload interface{}, respObj interface{}) (headers http.Header, err error) {
	client := c.getVirgilClient()
	headers, err = client.Send(method, url, token, payload, respObj)
	if err != nil {
		if apiErr, ok := err.(common.VirgilAPIError); ok {
			return headers, errors.NewServiceError(apiErr.Code, 0, apiErr.Message)
		}
		return headers, err
	}
	return headers, nil
}

func (c *PythiaClient) getUrl() string {
	if c.ServiceURL != "" {
		return c.ServiceURL
	}
	return "https://api.virgilsecurity.com"
}

func (c *PythiaClient) getHttpClient() common.HttpClient {
	if c.HttpClient != nil {
		return c.HttpClient
	}
	return http.DefaultClient
}

func (c *PythiaClient) getVirgilClient() *common.VirgilHttpClient {

	c.once.Do(func() {
		if c.VirgilHttpClient == nil {
			c.VirgilHttpClient = &common.VirgilHttpClient{
				Address: c.getUrl(),
				Client:  c.getHttpClient(),
			}
		}
	})

	return c.VirgilHttpClient
}

package pythia

import (
	"net/http"
	"sync"

	"gopkg.in/virgil.v5/common"
	"gopkg.in/virgil.v5/errors"
)

type Client struct {
	ServiceURL       string
	VirgilHttpClient *common.VirgilHttpClient
	HttpClient       common.HttpClient
	once             sync.Once
}

func NewClient(serviceURL string) *Client {
	return &Client{ServiceURL: serviceURL}
}

func (c *Client) ProtectPassword(salt, blindedPassword []byte, version uint, includeProof bool, token string) (*PasswordResp, error) {

	req := &PasswordReq{
		BlindedPassword: blindedPassword,
		IncludeProof:    includeProof,
		Version:         version,
		Salt:            salt,
	}

	var resp *PasswordResp
	_, err := c.send(http.MethodPost, "/pythia/v1/password", token, req, &resp)

	return resp, err
}

func (c *Client) send(method string, url string, token string, payload interface{}, respObj interface{}) (headers http.Header, err error) {
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

func (c *Client) getUrl() string {
	if c.ServiceURL != "" {
		return c.ServiceURL
	}
	return "https://api.virgilsecurity.com"
}

func (c *Client) getHttpClient() common.HttpClient {
	if c.HttpClient != nil {
		return c.HttpClient
	}
	return http.DefaultClient
}

func (c *Client) getVirgilClient() *common.VirgilHttpClient {

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

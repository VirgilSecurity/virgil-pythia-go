/*
 * BSD 3-Clause License
 *
 * Copyright (c) 2015-2018, Virgil Security, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 *  Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 *  Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

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
		UserId:          salt,
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

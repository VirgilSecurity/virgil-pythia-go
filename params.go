package pythia

import "github.com/pkg/errors"

type Params struct {
	ApiKey, ApiKeyID, AppID string

	ProofKeys []string
}

func MakeParams(apiKey, apiKeyId, appId string, proofKeys ...string) (*Params, error) {

	if apiKey == "" || apiKeyId == "" || appId == "" || len(proofKeys) == 0 {
		return nil, errors.New("not all parameters are set")
	}

	return &Params{
		ProofKeys: proofKeys,
		ApiKey:    apiKey,
		ApiKeyID:  apiKeyId,
		AppID:     appId,
	}, nil
}

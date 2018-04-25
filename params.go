package pythia

type Params struct {
	ApiKey, ApiKeyID, AppID string

	proofKeys ProofKeys
}

func MakeParams(apiKey, apiKeyId, appId string, proofKeys ...string) (*Params, error) {

	keys, err := NewProofKeys(proofKeys...)
	if err != nil {
		return nil, err
	}

	return &Params{
		proofKeys: keys,
		ApiKey:    apiKey,
		ApiKeyID:  apiKeyId,
		AppID:     appId,
	}, nil
}

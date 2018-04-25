package pythia

type PasswordReq struct {
	BlindedPassword []byte `json:"blinded_password"`
	IncludeProof    bool   `json:"include_proof"`
	Version         uint   `json:"version"`
	Salt            []byte `json:"salt"`
}

//
// PasswordResp is model for getting transform response
//
type PasswordResp struct {
	TransformedPassword []byte `json:"transformed_password"`
	Version             uint   `json:"version"`
	Proof               *Proof `json:"proof,omitempty"`
}

//
// Proof contains all necessary parameters for transformation correctness
//
type Proof struct {
	TransformationPublicKey []byte `json:"transformation_public_key"`
	ValueC                  []byte `json:"value_c"`
	ValueU                  []byte `json:"value_u"`
}

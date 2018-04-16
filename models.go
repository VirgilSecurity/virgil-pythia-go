package pythia

type PasswordReq struct {
	BlindedPassword []byte `json:"blinded_password"`
	IncludeProof    bool   `json:"include_proof"`
	Version         int    `json:"version"`
}

//
// PasswordResp is model for get password response
//
type PasswordResp struct {
	TransformedPassword []byte `json:"transformed_password"`
	Version             int    `json:"version"`
	Proof               *Proof `json:"proof,omitempty"`
}

//
// Proof contains all necessary parameters for proof of work
//
type Proof struct {
	TransformationPublicKey []byte `json:"transformation_public_key"`
	ValueC                  []byte `json:"value_c"`
	ValueU                  []byte `json:"value_u"`
}

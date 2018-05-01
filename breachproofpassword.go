package pythia

type BreachProofPassword struct {
	Salt, DeblindedPassword []byte
	Version                 uint
}

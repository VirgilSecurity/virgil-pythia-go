package pythia

type User struct {
	Salt, DeblindedPassword []byte
	Version                 uint
}

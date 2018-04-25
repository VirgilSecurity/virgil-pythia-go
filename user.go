package pythia

type User struct {
	Salt, DeblindedPassword []byte
	version                 uint
}

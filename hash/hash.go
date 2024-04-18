package hash

import "crypto/sha512"

type Function interface {
	GetFunctionName() string
	Hash(input []byte) ([64]byte, error)
}

type Sha512Function struct{}

var Sha512 = Sha512Function{}

func (hash *Sha512Function) GetFunctionName() string {
	return "SHA-512"
}

func (hash *Sha512Function) Hash(input []byte) ([64]byte, error) {
	return sha512.Sum512(input), nil
}

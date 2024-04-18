package public

import (
	"github.com/linckode/circl/ecc/fourq"
	"github.com/linckode/go-schnorrq/hash"
)

type Generator interface {
	Generate(privateKey [32]byte) [32]byte
}

type BasicSchnorrQGenerator struct{}

var DefaultGenerator = BasicSchnorrQGenerator{}

func (function *BasicSchnorrQGenerator) Generate(privateKey [32]byte) [32]byte {

	var point fourq.Point
	point.SetGenerator()

	//We don't handle the error because Sha512.Hash() doesn't return an error
	keyHash, _ := hash.Sha512.Hash(privateKey[:])

	var keyHashFirstHalf [32]byte
	copy(keyHashFirstHalf[:], keyHash[:32])

	point.ScalarBaseMult(&keyHashFirstHalf)

	var pointEncoding [32]byte
	point.Marshal(&pointEncoding)

	return pointEncoding
}

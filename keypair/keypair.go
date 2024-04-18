package keypair

import (
	"encoding/hex"
	"fmt"
	"github.com/linckode/go-schnorrq/keypair/public"
)

type KeyPair struct {
	PrivateKey [32]byte
	PublicKey  [32]byte
}

func New(privateKey, publicKey [32]byte) KeyPair {

	keyPair := KeyPair{}

	keyPair.PrivateKey = privateKey
	keyPair.PublicKey = publicKey

	return keyPair
}

func NewFromPrivateKey(privateKey [32]byte, function public.Generator) KeyPair {
	return New(privateKey, function.Generate(privateKey))
}

func (pair *KeyPair) Print() {
	fmt.Printf("Private key: %s\nPublic key:  %s\n",
		hex.EncodeToString(pair.PrivateKey[:]),
		hex.EncodeToString(pair.PublicKey[:]))

}

package ctx

import (
	"fmt"
	"github.com/linckode/schnorrq/core"
	"github.com/linckode/schnorrq/hash"
	"github.com/linckode/schnorrq/keypair"
	"github.com/pkg/errors"
)

type SchnorrQContext struct {
	hashFunction hash.Function
}

var DefaultContext = SchnorrQContext{
	hashFunction: &hash.Sha512,
}

func New(function hash.Function) SchnorrQContext {

	var context SchnorrQContext
	context.hashFunction = function
	return context
}

func (context *SchnorrQContext) Sign(pair keypair.KeyPair, message []byte) ([64]byte, error) {

	signature, err := core.Sign(pair.PrivateKey, pair.PublicKey, message, context.hashFunction)
	if err != nil {
		return [64]byte{}, errors.Wrap(err, fmt.Sprintf("signing using hash %s", context.hashFunction.GetFunctionName()))
	}
	return signature, nil
}

func (context *SchnorrQContext) Verify(pair keypair.KeyPair, message []byte, signature [64]byte) error {

	err := core.Verify(pair.PublicKey, message, signature, context.hashFunction)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("verifying signature using hash %s", context.hashFunction.GetFunctionName()))
	}
	return nil
}

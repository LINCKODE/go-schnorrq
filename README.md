# go-schnorrq

This Go module implements the generation and verification of Schnorr signatures on the FourQ elliptic curve.

## Features

- Simple and easy to use
- Allows for custom hash functions
- Allows for custom public key generator functions

## Usage

### Signature generation

```go

package main

import (
	"encoding/hex"
	"fmt"
	"github.com/linckode/go-schnorrq/ctx"
	"github.com/linckode/go-schnorrq/keypair"
	"github.com/linckode/go-schnorrq/keypair/public"
)

func _() {

	//Fill with your data
	privateKey := [32]byte{}
	message := [32]byte{}

	//The default context is based around the SHA-512 algorithm.
	context := ctx.DefaultContext

	//The default generator uses the default FourQLib method.
	pair := keypair.NewFromPrivateKey(privateKey, &public.DefaultGenerator)

	signature, err := context.Sign(pair, message[:])
	if err != nil {
		fmt.Printf("Encountered error while singining: %s", err.Error())
		return
	}
	fmt.Printf("Signature: %s\n", hex.EncodeToString(signature[:]))
}

```

### Signature verification

```go

package main

import (
	"fmt"
	"github.com/linckode/go-schnorrq/ctx"
	"github.com/linckode/go-schnorrq/keypair"
	"github.com/linckode/go-schnorrq/keypair/public"
)

func _() {

	//Fill with your data
	privateKey := [32]byte{}
	message := [32]byte{}
	signature := [64]byte{}

	//The default context is based around the SHA-512 algorithm.
	context := ctx.DefaultContext

	//The default generator uses the default FourQLib method.
	pair := keypair.NewFromPrivateKey(privateKey, &public.DefaultGenerator)

	err := context.Verify(pair, message[:], signature)
	if err != nil {
		fmt.Printf("Encountered error while verifying signature: %s", err.Error())
		return
	}

	fmt.Printf("Signature verifies!\n")
}

```

### Using custom hashing algorithms

KangarooTwelve example

```go

package main

import (
	"github.com/linckode/circl/xof/k12"
	"github.com/linckode/go-schnorrq/ctx"
	"github.com/linckode/go-schnorrq/keypair"
	"github.com/linckode/go-schnorrq/keypair/public"
	"github.com/pkg/errors"
)


type K12Function struct{}

func (hash *K12Function) GetFunctionName() string {
	return "KangarooTwelve"
}

func (hash *K12Function) Hash(input []byte) ([64]byte, error) {
	state := k12.NewDraft10([]byte{})
	_, err := state.Write(input)
	if err != nil {
		return [64]byte{}, errors.Wrap(err, "kangaroo-twelve hashing")
	}
	var out = [64]byte{}
	_, err = state.Read(out[:])
	if err != nil {
		return [64]byte{}, errors.Wrap(err, "reading kangaroo-twelve digest")
	}
	return out, nil
}


func _() {

	K12Context := ctx.SchnorrQContext{
		HashFunction: &K12Function{},
	}
	
	//K12Context.Sign()...
	//K12Context.Verify()...
	
}
```

### Using custom public key generator functions

```go

package main

import (
	"github.com/linckode/circl/ecc/fourq"
	"github.com/linckode/go-schnorrq/keypair"
)

type TestGenerator struct{}

func (function *TestGenerator) Generate(privateKey [32]byte) [32]byte {

	var point fourq.Point
	point.ScalarBaseMult(&privateKey)

	publicKey := [32]byte{}
	point.Marshal(&publicKey)

	return publicKey
}

func _() {
	
	//Fill with data
	privateKey := [32]byte{}
	pair := keypair.NewFromPrivateKey(privateKey, &TestGenerator{})
	
}
```





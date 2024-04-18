package schnorrq

import (
	"encoding/hex"
	"github.com/linckode/go-schnorrq/ctx"
	"github.com/linckode/go-schnorrq/keypair"
	"github.com/linckode/go-schnorrq/keypair/public"
	"testing"
)

func Test(t *testing.T) {

	privateKey := [32]byte{
		0xff, 0x98, 0x80, 0x66, 0xa7, 0xac, 0x75, 0x43,
		0xcf, 0x62, 0x79, 0x57, 0x2f, 0xc3, 0x90, 0xbf,
		0xd3, 0xe1, 0x91, 0xbb, 0x5d, 0x53, 0xf8, 0xee,
		0xd9, 0x78, 0xa6, 0x58, 0xce, 0x92, 0x7c, 0xe1,
	}

	message := [32]byte{
		0xa6, 0x82, 0x8f, 0xcb, 0x9b, 0x68, 0x6f, 0x08,
		0x74, 0x08, 0x57, 0x2b, 0xf3, 0x16, 0xe8, 0x9b,
		0x2d, 0x96, 0xfc, 0x48, 0x11, 0xb5, 0xd0, 0x75,
		0x4b, 0xfd, 0xbd, 0x5b, 0x8a, 0xd7, 0x76, 0x0d,
	}

	context := ctx.DefaultContext

	pair := keypair.NewFromPrivateKey(privateKey, &public.DefaultGenerator)

	signature, err := context.Sign(pair, message[:])
	if err != nil {
		t.Errorf("Encountered error while singining: %s", err.Error())
		return
	}

	t.Logf("Signature: %s\n", hex.EncodeToString(signature[:]))

	err = context.Verify(pair, message[:], signature)
	if err != nil {
		t.Errorf("Encountered error while verifying signature: %s", err.Error())
		return
	}
	t.Logf("Generated signature verifies!")

}

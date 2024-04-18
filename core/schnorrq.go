package core

import (
	"github.com/linckode/circl/ecc/fourq"
	"github.com/linckode/go-schnorrq/hash"
	"github.com/linckode/go-schnorrq/montgomery"
	"github.com/pkg/errors"
)

func Sign(privateKey, publicKey [32]byte, messageDigest []byte, hashFunction hash.Function) ([64]byte, error) {

	// Hash private key
	privateKeyHash, err := hashFunction.Hash(privateKey[:])
	if err != nil {
		return [64]byte{}, errors.Wrap(err, "hashing private key")
	}

	buffer := make([]byte, len(messageDigest)+64)

	//Second part of buffer is the first half of private key hash
	copy(buffer[32:], privateKeyHash[32:])
	//Last part of buffer is the message
	copy(buffer[64:], messageDigest[:])

	//Hash last two parts of the buffer. First part is not set for now.
	privateKeyMessageHash, err := hashFunction.Hash(buffer[32:])
	if err != nil {
		return [64]byte{}, errors.Wrap(err, "hashing private key + message")
	}

	//Initialize FourQ point
	var point fourq.Point

	//Use first 32 bytes of the privateKey + message hash as scalar for point multiplication
	var scalar [32]byte
	copy(scalar[:], privateKeyMessageHash[:32])

	//Perform fixed base multiplication (point = scalar * generator)
	point.ScalarBaseMult(&scalar)

	//Encode point into 32 byte array
	var pointEncoding [32]byte
	point.Marshal(&pointEncoding)

	//Copy point encoding into first part of the buffer
	copy(buffer[:32], pointEncoding[:])

	//Replace second part of the buffer with the public key
	copy(buffer[32:], publicKey[:])

	//Hash buffer
	bufferHash, err := hashFunction.Hash(buffer[:])
	if err != nil {
		return [64]byte{}, errors.Wrap(err, "hashing buffer")
	}

	//Montgomery shenanigans

	var montgomeryPrivateKeyMessageHash montgomery.Number
	err = montgomeryPrivateKeyMessageHash.FromStandard(privateKeyMessageHash[:32], montgomery.LittleEndian, true)
	if err != nil {
		return [64]byte{}, errors.Wrap(err, "creating montgomery number from private key + message hash")
	}

	var montgomeryBufferHash montgomery.Number
	err = montgomeryBufferHash.FromStandard(bufferHash[:32], montgomery.LittleEndian, true)
	if err != nil {
		return [64]byte{}, errors.Wrap(err, "creating montgomery number from buffer hash")
	}

	var montgomeryPrivateKeyHash montgomery.Number
	err = montgomeryPrivateKeyHash.FromStandard(privateKeyHash[:32], montgomery.LittleEndian, false)
	if err != nil {
		return [64]byte{}, errors.Wrap(err, "creating montgomery number from private key hash")
	}

	//Perform multiplication
	montgomeryPrivateKeyHash.Multiply(montgomeryPrivateKeyHash, montgomeryBufferHash)

	//Perform subtraction
	montgomeryPrivateKeyHash.Subtract(montgomeryPrivateKeyMessageHash, montgomeryPrivateKeyHash)

	//Assemble signature
	var signature [64]byte

	//First part
	copy(signature[:32], pointEncoding[:])

	//Second part
	array := montgomeryPrivateKeyHash.ToStandard()
	copy(signature[32:], array[:])

	return signature, nil
}

func Verify(publicKey [32]byte, messageDigest []byte, signature [64]byte, hashFunction hash.Function) error {

	//Check input validity
	if (publicKey[15]&0x80 != 0) || (signature[15]&0x80 != 0) || (signature[62]&0xC0 != 0) || signature[63] != 0 {
		return errors.New("bad public key or signature")
	}

	//Initialize point
	var point fourq.Point

	//Initialize buffer
	var buffer = make([]byte, len(messageDigest)+64)

	//Decode public key
	if !point.Unmarshal(&publicKey) {
		return errors.New("failed to decode public key")
	}

	//First part is the first part of signature
	copy(buffer[:32], signature[:32])
	//Second part is the public key
	copy(buffer[32:], publicKey[:])
	//Third part is the message
	copy(buffer[64:], messageDigest[:])

	//Hash the buffer
	bufferHash, err := hashFunction.Hash(buffer)
	if err != nil {
		return errors.Wrap(err, "failed to hash buffer")
	}

	//First part of signature
	var signatureFirstPart [32]byte
	copy(signatureFirstPart[:], signature[:32])

	//Last part of signature
	var signatureLastPart [32]byte
	copy(signatureLastPart[:], signature[32:])

	//First part of buffer hash
	var bufferHashFirstPart [32]byte
	copy(bufferHashFirstPart[:], bufferHash[:32])

	//Perform double scalar multiplication
	point.DoubleScalarMult(&signatureLastPart, &point, &bufferHashFirstPart)

	//Point encoding
	var encoding [32]byte
	point.Marshal(&encoding)

	//Check first part of signature against encoded point
	if encoding != signatureFirstPart {
		return errors.New("signature does not verify")
	}

	return nil
}

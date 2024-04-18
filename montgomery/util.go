package montgomery

import (
	"github.com/linckode/go-schnorrq/order"
	"math/big"
)

func reverseEndianness(array []byte) []byte {

	length := len(array)
	reverse := make([]byte, length)

	for i := 0; i < length; i++ {
		reverse[i] = array[length-i-1]
	}
	return reverse
}

func modOrder(array [32]byte, endian Endianness) [32]byte {
	return elementToStandard(elementFromStandard(array, endian), endian)
}

func elementFromStandard(array [32]byte, endian Endianness) order.Element {
	var element order.Element

	switch endian {
	case BigEndian:
		element.SetBigInt(new(big.Int).SetBytes(array[:]))
		break

	case LittleEndian:
		element.SetBigInt(new(big.Int).SetBytes(reverseEndianness(array[:])))
		break
	}

	return element

}

func elementToStandard(element order.Element, endian Endianness) [32]byte {
	var array [32]byte

	switch endian {
	case BigEndian:
		order.BigEndian.PutElement(&array, element)
		break
	case LittleEndian:
		order.LittleEndian.PutElement(&array, element)
		break
	}
	return array
}

package montgomery

import (
	"github.com/linckode/go-schnorrq/order"
	"github.com/pkg/errors"
)

type Number struct {
	orderElement order.Element
	endianness   Endianness
}

func (number *Number) FromStandard(array []byte, endian Endianness, doModOrder bool) error {

	if len(array) != 32 {
		return errors.New("cannot create Montgomery number, input array is not 32 bytes long")
	}

	var data [32]byte
	copy(data[:], array[:])

	//If we have to mod order the number first
	if doModOrder {
		data = modOrder(data, endian)
	}

	number.endianness = endian
	number.orderElement = elementFromStandard(data, endian)

	return nil
}

func (number *Number) ToStandard() [32]byte {
	return elementToStandard(number.orderElement, number.endianness)
}

func (number *Number) Multiply(ma, mb Number) {

	var element order.Element

	element.Mul(&ma.orderElement, &mb.orderElement)

	number.orderElement = element
	number.endianness = ma.endianness
}

func (number *Number) Subtract(ma, mb Number) {

	var element order.Element

	element.Sub(&ma.orderElement, &mb.orderElement)

	number.orderElement = element
	number.endianness = ma.endianness
}

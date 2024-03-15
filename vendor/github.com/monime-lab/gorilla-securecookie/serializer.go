package securecookie

import (
	"bytes"
	"encoding/json"
)

// Serializer provides an interface for providing custom serializers for cookie
// values.
type Serializer interface {
	Serialize(src interface{}) ([]byte, error)
	Deserialize(src []byte, dst interface{}) error
}

// JSONEncoder encodes cookie values using encoding/json. Users who wish to
// encode complex types need to satisfy the json.Marshaller and
// json.Unmarshaller interfaces.
type JSONEncoder struct{}

// Serialize encodes a value using encoding/json.
func (e JSONEncoder) Serialize(src interface{}) ([]byte, error) {
	buf := new(bytes.Buffer)
	enc := json.NewEncoder(buf)
	if err := enc.Encode(src); err != nil {
		return nil, Error{msg: err.Error()}
	}
	return buf.Bytes(), nil
}

// Deserialize decodes a value using encoding/json.
func (e JSONEncoder) Deserialize(src []byte, dst interface{}) error {
	dec := json.NewDecoder(bytes.NewReader(src))
	if err := dec.Decode(dst); err != nil {
		return Error{msg: err.Error()}
	}
	return nil
}

// NopEncoder does not encode cookie values, and instead simply accepts a []byte
// (as an interface{}) and returns a []byte. This is particularly useful when
// you're encoding an object upstream and do not wish to re-encode it.
type NopEncoder struct{}

// Serialize passes a []byte through as-is.
func (e NopEncoder) Serialize(src interface{}) ([]byte, error) {
	if b, ok := src.([]byte); ok {
		return b, nil
	}

	return nil, errValueNotByte
}

// Deserialize passes a []byte through as-is.
func (e NopEncoder) Deserialize(src []byte, dst interface{}) error {
	if dat, ok := dst.(*[]byte); ok {
		*dat = src
		return nil
	}
	return errValueNotBytePtr
}

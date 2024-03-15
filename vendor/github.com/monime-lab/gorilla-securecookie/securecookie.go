// Copyright 2012 The Gorilla Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package securecookie

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"
	"time"
)

type Error struct {
	msg string
}

func (e Error) Error() string {
	parts := []string{"securecookie: "}
	if e.msg == "" {
		parts = append(parts, "error")
	} else {
		parts = append(parts, e.msg)
	}
	return strings.Join(parts, "")
}

var (
	errGeneratingIV = Error{msg: "failed to generate random iv"}

	errNoCodecs            = Error{msg: "no codecs provided"}
	errHashKeyNotSet       = Error{msg: "hash key is not set"}
	errBlockKeyNotSet      = Error{msg: "block key is not set"}
	errEncodedValueTooLong = Error{msg: "the value is too long"}

	errValueToDecodeTooLong = Error{msg: "the value is too long"}
	errNameIsUnexpected     = Error{msg: "name is unexpected"}
	errTimestampTooNew      = Error{msg: "timestamp is too new"}
	errTimestampExpired     = Error{msg: "expired timestamp"}
	errDecryptionFailed     = Error{msg: "the value could not be decrypted"}
	errValueNotByte         = Error{msg: "value not a []byte."}
	errValueNotBytePtr      = Error{msg: "value not a pointer to []byte."}

	// ErrMacInvalid indicates that cookie decoding failed because the HMAC
	// could not be extracted and verified.  Direct use of this error
	// variable is deprecated; it is public only for legacy compatibility,
	// and may be privatized in the future, as it is rarely useful to
	// distinguish between this error and other Error implementations.
	ErrMacInvalid = Error{msg: "the value is not valid"}
)

// Codec defines an interface to encode and decode cookie values.
type Codec interface {
	Encode(name string, value interface{}) (string, error)
	Decode(name, value string, dst interface{}) error
}

// New returns a new SecureCookie.
//
// hashKey is required, used to authenticate values using HMAC. Create it using
// GenerateRandomKey(). It is recommended to use a key with 32 or 64 bytes.
//
// blockKey is optional, used to encrypt values. Create it using
// GenerateRandomKey(). The key length must correspond to the key size
// of the encryption algorithm. For AES, used by default, valid lengths are
// 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256.
// The default encoder used for cookie serialization is encoding/gob.
//
// Note that keys created using GenerateRandomKey() are not automatically
// persisted. New keys will be created when the application is restarted, and
// previously issued cookies will not be able to be decoded.
func New(hashKey, blockKey []byte) *SecureCookie {
	cookie := &SecureCookie{
		hashKey:   hashKey,
		blockKey:  blockKey,
		hashFunc:  sha256.New,
		maxAge:    86400 * 30,
		maxLength: 4096,
		sz:        JSONEncoder{},
	}
	if len(hashKey) == 0 {
		panic(errHashKeyNotSet)
	}
	if blockKey != nil {
		cookie.BlockFunc(aes.NewCipher)
	}
	return cookie
}

// SecureCookie encodes and decodes authenticated and optionally encrypted
// cookie values.
type SecureCookie struct {
	hashKey   []byte
	hashFunc  func() hash.Hash
	blockKey  []byte
	block     cipher.Block
	maxLength int
	maxAge    int64
	minAge    int64
	err       error
	sz        Serializer
	// For testing purposes, the function that returns the current timestamp.
	// If not set, it will use time.Now().UTC().Unix().
	timeFunc func() int64
}

// MaxLength restricts the maximum length, in bytes, for the cookie value.
//
// Default is 4096, which is the maximum value accepted by Internet Explorer.
func (s *SecureCookie) MaxLength(value int) *SecureCookie {
	s.maxLength = value
	return s
}

// MaxAge restricts the maximum age, in seconds, for the cookie value.
//
// Default is 86400 * 30. Set it to 0 for no restriction.
func (s *SecureCookie) MaxAge(value int) *SecureCookie {
	s.maxAge = int64(value)
	return s
}

// MinAge restricts the minimum age, in seconds, for the cookie value.
//
// Default is 0 (no restriction).
func (s *SecureCookie) MinAge(value int) *SecureCookie {
	s.minAge = int64(value)
	return s
}

// HashFunc sets the hash function used to create HMAC.
//
// Default is crypto/sha256.New.
func (s *SecureCookie) HashFunc(f func() hash.Hash) *SecureCookie {
	s.hashFunc = f
	return s
}

// BlockFunc sets the encryption function used to create a cipher.Block.
//
// Default is crypto/aes.New.
func (s *SecureCookie) BlockFunc(f func([]byte) (cipher.Block, error)) *SecureCookie {
	if s.blockKey == nil {
		s.err = errBlockKeyNotSet
	} else if block, err := f(s.blockKey); err == nil {
		s.block = block
	} else {
		s.err = err
	}
	return s
}

// Encoding sets the encoding/serialization method for cookies.
//
// Default is encoding/gob.  To encode special structures using encoding/gob,
// they must be registered first using gob.Register().
func (s *SecureCookie) SetSerializer(sz Serializer) *SecureCookie {
	s.sz = sz

	return s
}

// Encode encodes a cookie value.
//
// It serializes, optionally encrypts, signs with a message authentication code,
// and finally encodes the value.
//
// The name argument is the cookie name. It is stored with the encoded value.
// The value argument is the value to be encoded. It can be any value that can
// be encoded using the currently selected serializer; see SetSerializer().
//
// It is the client's responsibility to ensure that value, when encoded using
// the current serialization/encryption settings on s and then base64-encoded,
// is shorter than the maximum permissible length.
func (s *SecureCookie) Encode(name string, value interface{}) (string, error) {
	if s.err != nil {
		return "", s.err
	}
	if s.hashKey == nil {
		s.err = errHashKeyNotSet
		return "", s.err
	}
	// 1. Serialize.
	data, err := s.sz.Serialize(value)
	if err != nil {
		return "", err
	}
	// 2. Encrypt (optional).
	if s.block != nil {
		if data, err = encrypt(s.block, data); err != nil {
			return "", err
		}
	}
	buf := new(bytes.Buffer)
	name = s.sanitizeName(name)
	if err = binary.Write(buf, binary.LittleEndian, uint16(len(name))); err != nil {
		return "", err
	}
	ts := s.timestamp()
	buf.WriteString(name)
	if err = binary.Write(buf, binary.LittleEndian, uint64(ts)); err != nil {
		return "", err
	}
	buf.Write(data)
	payload := buf.Bytes()
	mac := createMac(hmac.New(s.hashFunc, s.hashKey), payload)
	// 4. Encode to base64.
	out := make([]byte, len(payload)+len(mac))
	copy(out[:len(mac)], mac)
	copy(out[len(mac):], payload)
	out = encode(out)
	// 5. Check length.
	if s.maxLength != 0 && len(out) > s.maxLength {
		return "", fmt.Errorf("%w: %d", errEncodedValueTooLong, len(out))
	}
	// Done.
	return string(out), nil
}

// Decode decodes a cookie value.
//
// It decodes, verifies a message authentication code, optionally decrypts and
// finally deserializes the value.
//
// The name argument is the cookie name. It must be the same name used when
// it was stored. The value argument is the encoded cookie value. The dst
// argument is where the cookie will be decoded. It must be a pointer.
func (s *SecureCookie) Decode(name, value string, dst interface{}) error {
	if s.err != nil {
		return s.err
	}
	if s.hashKey == nil {
		s.err = errHashKeyNotSet
		return s.err
	}
	name = s.sanitizeName(name)
	// 1. Check length.
	if s.maxLength != 0 && len(value) > s.maxLength {
		return fmt.Errorf("%w: %d", errValueToDecodeTooLong, len(value))
	}
	// 2. Decode from base64.
	b, err := decode([]byte(value))
	if err != nil {
		return err
	}
	h := hmac.New(s.hashFunc, s.hashKey)
	mac, payload := b[:32], b[32:]
	if err = verifyMac(h, payload, mac); err != nil {
		return err
	}
	nameLen := binary.LittleEndian.Uint16(payload[:2])
	n := string(payload[2 : 2+nameLen])
	ts := int64(binary.LittleEndian.Uint64(payload[2+nameLen:]))
	data := payload[2+nameLen+8:]
	if n != name {
		return fmt.Errorf("%w: %s", errNameIsUnexpected, name)
	}
	// 4. Verify date ranges.
	t2 := s.timestamp()
	if s.minAge != 0 && ts > t2-s.minAge {
		return errTimestampTooNew
	}
	if s.maxAge != 0 && ts < t2-s.maxAge {
		return errTimestampExpired
	}
	// 5. Decrypt (optional).
	if s.block != nil {
		if data, err = decrypt(s.block, data); err != nil {
			return err
		}
	}
	// 6. Deserialize.
	if err = s.sz.Deserialize(data, dst); err != nil {
		return Error{msg: err.Error()}
	}
	return nil
}

// timestamp returns the current timestamp, in seconds.
//
// For testing purposes, the function that generates the timestamp can be
// overridden. If not set, it will return time.Now().UTC().Unix().
func (s *SecureCookie) timestamp() int64 {
	if s.timeFunc == nil {
		return time.Now().UTC().Unix()
	}
	return s.timeFunc()
}

func (s *SecureCookie) sanitizeName(name string) string {
	name = strings.TrimPrefix(name, "__Secure-")
	name = strings.TrimPrefix(name, "__Host-")
	return name
}

// Authentication -------------------------------------------------------------

// createMac creates a message authentication code (MAC).
func createMac(h hash.Hash, value []byte) []byte {
	h.Write(value)
	return h.Sum(nil)
}

// verifyMac verifies that a message authentication code (MAC) is valid.
func verifyMac(h hash.Hash, value []byte, mac []byte) error {
	mac2 := createMac(h, value)
	// Check that both MACs are of equal length, as subtle.ConstantTimeCompare
	// does not do this prior to Go 1.4.
	if len(mac) == len(mac2) && subtle.ConstantTimeCompare(mac, mac2) == 1 {
		return nil
	}
	return ErrMacInvalid
}

// Encryption -----------------------------------------------------------------

// encrypt encrypts a value using the given block in counter mode.
//
// A random initialization vector ( https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Initialization_vector_(IV) ) with the length of the
// block size is prepended to the resulting ciphertext.
func encrypt(block cipher.Block, value []byte) ([]byte, error) {
	iv := GenerateRandomKey(block.BlockSize())
	if iv == nil {
		return nil, errGeneratingIV
	}
	// Encrypt it.
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(value, value)
	// Return iv + ciphertext.
	return append(iv, value...), nil
}

// decrypt decrypts a value using the given block in counter mode.
//
// The value to be decrypted must be prepended by a initialization vector
// ( https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Initialization_vector_(IV) ) with the length of the block size.
func decrypt(block cipher.Block, value []byte) ([]byte, error) {
	size := block.BlockSize()
	if len(value) > size {
		// Extract iv.
		iv := value[:size]
		// Extract ciphertext.
		value = value[size:]
		// Decrypt it.
		stream := cipher.NewCTR(block, iv)
		stream.XORKeyStream(value, value)
		return value, nil
	}
	return nil, errDecryptionFailed
}

// Encoding -------------------------------------------------------------------

// encode encodes a value using base64.
func encode(value []byte) []byte {
	encoded := make([]byte, base64.URLEncoding.EncodedLen(len(value)))
	base64.URLEncoding.Encode(encoded, value)
	return encoded
}

// decode decodes a cookie using base64.
func decode(value []byte) ([]byte, error) {
	decoded := make([]byte, base64.URLEncoding.DecodedLen(len(value)))
	b, err := base64.URLEncoding.Decode(decoded, value)
	if err != nil {
		return nil, Error{msg: "base64 decode failed"}
	}
	return decoded[:b], nil
}

// Helpers --------------------------------------------------------------------

// GenerateRandomKey creates a random key with the given length in bytes.
// On failure, returns nil.
//
// Note that keys created using `GenerateRandomKey()` are not automatically
// persisted. New keys will be created when the application is restarted, and
// previously issued cookies will not be able to be decoded.
//
// Callers should explicitly check for the possibility of a nil return, treat
// it as a failure of the system random number generator, and not continue.
func GenerateRandomKey(length int) []byte {
	k := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return nil
	}
	return k
}

// CodecsFromPairs returns a slice of SecureCookie instances.
//
// It is a convenience function to create a list of codecs for key rotation. Note
// that the generated Codecs will have the default options applied: callers
// should iterate over each Codec and type-assert the underlying *SecureCookie to
// change these.
//
// Example:
//
//	codecs := securecookie.CodecsFromPairs(
//	     []byte("new-hash-key"),
//	     []byte("new-block-key"),
//	     []byte("old-hash-key"),
//	     []byte("old-block-key"),
//	 )
//
//	// Modify each instance.
//	for _, s := range codecs {
//	       if cookie, ok := s.(*securecookie.SecureCookie); ok {
//	           cookie.MaxAge(86400 * 7)
//	           cookie.SetSerializer(securecookie.JSONEncoder{})
//	           cookie.HashFunc(sha512.New512_256)
//	       }
//	   }
func CodecsFromPairs(keyPairs ...[]byte) []Codec {
	codecs := make([]Codec, len(keyPairs)/2+len(keyPairs)%2)
	for i := 0; i < len(keyPairs); i += 2 {
		var blockKey []byte
		if i+1 < len(keyPairs) {
			blockKey = keyPairs[i+1]
		}
		codecs[i/2] = New(keyPairs[i], blockKey)
	}
	return codecs
}

// EncodeMulti encodes a cookie value using a group of codecs.
//
// The codecs are tried in order. Multiple codecs are accepted to allow
// key rotation.
//
// On error, may return a MultiError.
func EncodeMulti(name string, value interface{}, codecs ...Codec) (string, error) {
	if len(codecs) == 0 {
		return "", errNoCodecs
	}

	var errs []error
	for _, codec := range codecs {
		encoded, err := codec.Encode(name, value)
		if err == nil {
			return encoded, nil
		}
		errs = append(errs, err)
	}
	return "", errors.Join(errs...)
}

// DecodeMulti decodes a cookie value using a group of codecs.
//
// The codecs are tried in order. Multiple codecs are accepted to allow
// key rotation.
//
// On error, may return a MultiError.
func DecodeMulti(name string, value string, dst interface{}, codecs ...Codec) error {
	if len(codecs) == 0 {
		return errNoCodecs
	}

	var errs []error
	for _, codec := range codecs {
		err := codec.Decode(name, value, dst)
		if err == nil {
			return nil
		}
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

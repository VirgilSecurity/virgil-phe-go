package phe

import (
	"crypto/sha512"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/hkdf"
)

//TupleHash hashes a slice of byte arrays, prefixing each one with its length
func TupleHash(tuple [][]byte, domain []byte) ([]byte, error) {
	var sizeBuf [8]byte
	hash := sha512.New512_256()

	for _, t := range tuple {
		if err := writeArray(hash, &sizeBuf, t); err != nil {
			return nil, err
		}
	}
	if err := writeArray(hash, &sizeBuf, domain); err != nil {
		return nil, err
	}
	return hash.Sum(nil), nil
}

func writeArray(w io.Writer, sizeBuf *[8]byte, a []byte) (err error) {
	binary.BigEndian.PutUint64(sizeBuf[:], uint64(len(a)))
	if _, err = w.Write(sizeBuf[:]); err != nil {
		return
	}
	if _, err = w.Write(a); err != nil {
		return
	}
	return
}

// TupleKDF creates HKDF instance initialized with TupleHash
func TupleKDF(tuple [][]byte, domain []byte) (io.Reader, error) {
	key, err := TupleHash(tuple, domain)
	if err != nil {
		return nil, err
	}

	return hkdf.New(sha512.New512_256, key, domain, []byte("TupleKDF")), nil

}

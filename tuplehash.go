package phe

import (
	"crypto/sha512"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/hkdf"
)

//TupleHash hashes a slice of byte arrays, prefixing each one with its length
func TupleHash(tuple [][]byte, domain []byte) []byte {
	var sizeBuf [8]byte
	hash := sha512.New512_256()

	for _, t := range tuple {
		writeArray(hash, &sizeBuf, t)
	}
	writeArray(hash, &sizeBuf, domain)
	return hash.Sum(nil)
}

func writeArray(w io.Writer, sizeBuf *[8]byte, a []byte) {
	binary.BigEndian.PutUint64(sizeBuf[:], uint64(len(a)))
	w.Write(sizeBuf[:])
	w.Write(a)
}

// TupleKDF creates HKDF instance initialized with TupleHash
func TupleKDF(tuple [][]byte, domain []byte) io.Reader {
	key := TupleHash(tuple, domain)
	return hkdf.New(sha512.New512_256, key, domain, []byte("TupleKDF"))

}

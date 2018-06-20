package phe

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"testing"
)

func Test_PHE(t *testing.T) {

	skR, _, _, _ := elliptic.GenerateKey(elliptic.P256(), rand.Reader)
	skS, _, _, _ := elliptic.GenerateKey(elliptic.P256(), rand.Reader)

	l := &RateLimiter{skR}
	s := &Server{skS}

	nr, c0, c1 := l.Encrypt()

	ns, m, t1, t2 := s.Encrypt([]byte("Password"), c0, c1)

	fmt.Println(nr, ns, m, t1, t2)

}

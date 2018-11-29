package phe

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncrypt(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	data := make([]byte, 365)

	ciphertext, err := Encrypt(data, key)

	require.NoError(t, err)

	plaintext, err := Decrypt(ciphertext, key)
	require.NoError(t, err)

	require.Equal(t, plaintext, data)

}

func TestEncrypt_empty(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	data := make([]byte, 0)

	ciphertext, err := Encrypt(data, key)

	require.NoError(t, err)

	plaintext, err := Decrypt(ciphertext, key)
	require.NoError(t, err)

	require.Equal(t, plaintext, data)

}

func TestEncrypt_badKey(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	data := make([]byte, 365)

	ciphertext, err := Encrypt(data, key)

	require.NoError(t, err)

	key[0]++

	plaintext, err := Decrypt(ciphertext, key)
	require.Error(t, err)
	require.Nil(t, plaintext)
}

func TestDecrypt_badLength(t *testing.T) {
	ct := make([]byte, 32+15)
	key := make([]byte, 32)
	rand.Read(key)
	plaintext, err := Decrypt(ct, key)

	require.Error(t, err)
	require.Equal(t, err.Error(), "invalid ciphertext length")
	require.Nil(t, plaintext)
}

func TestHashZVector(t *testing.T) {

	pub := []byte{
		0x04, 0x21, 0xc3, 0x71, 0x95, 0x74, 0xaf, 0xce,
		0xc6, 0x5e, 0x35, 0xbd, 0x77, 0x5a, 0x5b, 0xe3,
		0x6c, 0x77, 0xc0, 0xbe, 0x45, 0x01, 0xf5, 0xd7,
		0x0f, 0xf0, 0x70, 0xd5, 0x1a, 0x89, 0x3a, 0xd8,
		0xe0, 0x0c, 0xe6, 0xb8, 0x9b, 0x17, 0x88, 0xe6,
		0xc1, 0x27, 0xa0, 0xe1, 0x25, 0xd9, 0xde, 0x6a,
		0x71, 0x16, 0x46, 0xa0, 0x38, 0x0f, 0xc4, 0xe9,
		0x5a, 0x74, 0xe5, 0x2c, 0x89, 0xf1, 0x12, 0x2a,
		0x7c,
	}

	c0X := "97803661066250274657510595696566855164534492744724548093309723513248461995097"
	c0Y := "32563640650805051226489658838020042684659728733816530715089727234214066735908"
	c1X := "83901588226167680046300869772314554609808129217097458603677198943293551162597"
	c1Y := "69578797673242144759724361924884259223786981560985539034793627438888366836078"
	t1X := "34051691470374495568913340263568595354597873005782528499014802063444122859583"
	t1Y := "55902370943165854960816059167184401667567213725158022607170263924097403943290"
	t2X := "101861885104337123215820986653465602199317278936192518417111183141791463240617"
	t2Y := "40785451420258280256125533532563267231769863378114083364571107590767796025737"
	t3X := "79689595215343344259388135277552904427007069090288122793121340067386243614518"
	t3Y := "63043970895569149637126206639504503565389755448934804609068720159153015056302"
	chlng := "44284775164038922154509064072457018313778507095510488730681838539467538456334"

	z := hashZ(proofOk, pub, curveG, Point2Bytes(c0X, c0Y), Point2Bytes(c1X, c1Y), Point2Bytes(t1X, t1Y), Point2Bytes(t2X, t2Y), Point2Bytes(t3X, t3Y))
	require.Equal(t, chlng, z.String())
}

func Point2Bytes(xs, ys string) []byte {
	x, _ := new(big.Int).SetString(xs, 10)
	y, _ := new(big.Int).SetString(ys, 10)

	p := &Point{
		X: x,
		Y: y,
	}

	return p.Marshal()
}

func TestSimpleHashZ(t *testing.T) {
	require.Equal(t, "97888341710369812510024597077129852329763301580926521329107926771848618239575", hashZ(proofOk, curveG).String())
}

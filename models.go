package phe

//ClientRecord stores all necessary password protection info
type ClientRecord struct {
	NS []byte `json:"ns"`
	NC []byte `json:"nc"`
	T0 []byte `json:"t_0"`
	T1 []byte `json:"t_1"`
}

// Proof contains data for client to validate
type Proof struct {
	Term1  []byte `json:"term_1,omitempty"`
	Term2  []byte `json:"term_2,omitempty"`
	Term3  []byte `json:"term_3,omitempty"`
	Term4  []byte `json:"term_4,omitempty"`
	BlindX []byte `json:"blind_x,omitempty"`
	BlindA []byte `json:"blind_a,omitempty"`
	BlindB []byte `json:"blind_b,omitempty"`
}

// UpdateToken contains values needed for value rotation
type UpdateToken struct {
	A []byte `json:"a"`
	B []byte `json:"b"`
}

type Enrollment struct {
	NS    []byte `json:"ns"`
	C0    []byte `json:"c_0"`
	C1    []byte `json:"c_1"`
	Proof *Proof `json:"proof"`
}

type VerifyPasswordRequest struct {
	NS []byte `json:"ns"`
	C0 []byte `json:"c_0"`
}

type VerifyPasswordResponse struct {
	Res   bool   `json:"res"`
	C1    []byte `json:"c_1"`
	Proof *Proof `json:"proof"`
}

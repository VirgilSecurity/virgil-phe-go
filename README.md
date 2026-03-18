# Password-Hardened Encryption (PHE) — Go SDK

[![Test](https://github.com/VirgilSecurity/virgil-phe-go/actions/workflows/test.yml/badge.svg)](https://github.com/VirgilSecurity/virgil-phe-go/actions/workflows/test.yml)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)

[Virgil Security](https://virgilsecurity.com) implementation of the [Password-Hardened Encryption (PHE) protocol](https://virgilsecurity.com/wp-content/uploads/2018/11/PHE-Whitepaper-2018.pdf) — protects user passwords from offline attacks and makes stolen passwords useless even if the database is compromised.

## Requirements

- Go 1.26+

## Installation

```bash
go get github.com/VirgilSecurity/virgil-phe-go
```

## Usage

### Server

```go
import phe "github.com/VirgilSecurity/virgil-phe-go"

// Generate server keypair
keypair, err := phe.GenerateServerKeypair()

// Create enrollment for a new user
enrollment, err := phe.GetEnrollment(keypair)

// Verify password
response, result, err := phe.VerifyPasswordExtended(keypair, request)

// Key rotation
token, newKeypair, err := phe.Rotate(keypair)
```

### Client

```go
// Create client
client, err := phe.NewClient(serverPublicKey, clientPrivateKey)

// Enroll user password
record, encryptionKey, err := client.EnrollAccount(password, enrollmentResponse)

// Create verify request
request, err := client.CreateVerifyPasswordRequest(password, record)

// Verify and decrypt
key, err := client.CheckResponseAndDecrypt(password, record, response)

// Update record after rotation
updatedRecord, err := phe.UpdateRecord(record, token)
```

### Encryption

```go
// AES-256-GCM encrypt/decrypt with HKDF key derivation
ciphertext, err := phe.Encrypt(data, key)
plaintext, err := phe.Decrypt(ciphertext, key)
```

## References

- **Authors**: Russell W. F. Lai, Christoph Egger, Manuel Reinert, Sherman S. M. Chow, Matteo Maffei and Dominique Schroder
- **WhitePaper**: https://virgilsecurity.com/wp-content/uploads/2018/11/PHE-Whitepaper-2018.pdf
- Go implementation by **Alexey Ermishkin** [VirgilSecurity, Inc.](https://virgilsecurity.com)

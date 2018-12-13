/*
 * Copyright (C) 2015-2018 Virgil Security Inc.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 */

package phe

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	serverPublic          = mustHex("04464173c0589a4dd70760f0fd8ddccf99ec829098d194e9c925403a35245d44f2acf6784fe4d7a5eb76ba0d23227625e0f264051c8ed36fe9088f210faa160a45")
	serverPrivate         = mustHex("403cde159ac7bafa8e04a88e3dcbaae06c3c2f46699c0a28344e5e54e3c460ca")
	clientPrivate         = mustHex("f587c094be766cf7d33120717bdf7e448cfea9c7ea69d4cae49f145e1f967b6c")
	enrollmentResponse    = mustHex("0a2056833a7a1cdb2ec991ca338cd4a2ed663770400fab2cd798bee9f3ed378796bd1241049979b7184b5e509d06707a6fef2c79049fa00f511577d44a39117c23c121d37b60c9063e325e198d8f7f8deb065477b48fc5c30a70c624a40787ad6a14c134631a41042bc12ce1460ab2a652c3a2378f57c0eb1ad7b49c594343983a77ca9a4303a983a28dc0c0f8b6a7a55be1c53dbc2c3cdd79f834382ec812783a038f1a9766b80522eb010a4104fa04982aadda8d63ed2a539720ad8da0acf67e566e36b6a89d42c8b7775f0b601c9335995d723952636b09d9bdd45f02693809153bdc7e2b2bff9e16d22b7bf6124104a994f4685bde3df0349d77939d6778ae7d0e999588edc806e03c11b7a3041b351270d3d0b5c0536668e661ee15164246666ce3f0b913c6c2d337f65cea69ce691a410410e4f1cb262c84f772587ebd8652ca0729ddbace7c8fca42993c149e1cac557f1f749f25e3721c7fa36a7b6fad93e7dedb9f78b05bd2effe245685cf19d736132220c688a79193465315692ef2a49559126fdf86e3b3572b12783f56980b4f4a71d2")
	password              = mustHex("7061737377307264")
	enrollmentRecord      = mustHex("0a2056833a7a1cdb2ec991ca338cd4a2ed663770400fab2cd798bee9f3ed378796bd122056833a7a1cdb2ec991ca338cd4a2ed663770400fab2cd798bee9f3ed378796bd1a4104cff0689055bc2eb58bafb4120f0b89f8793738f1c1777034b3c18c1f540ebf00ceee192f2f7667444eb6af32147b9faf7b98d24fac8bb3db53c97cad8fd33a41224104e3e6e4925cba1c4a6186daffa5a3dbee0734b211233f61116ace4410a26a46c828b71ad879bd3c7c26dfa4a0dfc773d3e0ed148369f9ab51156b1e7bede2d69e")
	recordKey             = mustHex("f0753d12220e1f1847b20e40ffc573c06103320b68d84b86627b2216aa0b2fef")
	verifyPasswordReq     = mustHex("0a2056833a7a1cdb2ec991ca338cd4a2ed663770400fab2cd798bee9f3ed378796bd1241049979b7184b5e509d06707a6fef2c79049fa00f511577d44a39117c23c121d37b60c9063e325e198d8f7f8deb065477b48fc5c30a70c624a40787ad6a14c13463")
	verifyPasswordResp    = mustHex("08011241042bc12ce1460ab2a652c3a2378f57c0eb1ad7b49c594343983a77ca9a4303a983a28dc0c0f8b6a7a55be1c53dbc2c3cdd79f834382ec812783a038f1a9766b8051aeb010a4104d081c0340b088b91db69f50a6ed7c36162eeb94903658169e0d73887886850558a5f82769b7a19ee39d8a18fcd5a547123411e8dfdae9c89796597aa54a6765f124104a72fbec0682d5027d0028ffde7009d74990943a2a5822d295f2a33121889f56b85ab24183148158b9b6f53538858ff624c50574da93fa4427820d6808a45df8d1a4104d373e5a27ff3153e96b01924479bc50cae80f0e55a35ccfdbc92a839ace4005fe7d9b96d5be40d490043ed021b29b7d14bae0d6e07a4707538e64773403665cb2220ebc69e0a0807de0fe28c8073bfd2dc3dfbe7ff35d6a192442575e9e5da4a6fac")
	badPassword           = mustHex("7040737377307264")
	verifyBadPasswordReq  = mustHex("0a2056833a7a1cdb2ec991ca338cd4a2ed663770400fab2cd798bee9f3ed378796bd1241040b43a6e0831d2ca5f92d0e7fc056a9ad7aff9bfc98096b4ca667521676018aed054e963346cb53a544bb751e5302686be2fc8c18ee18172cbed5dba57767d799")
	verifyBadPasswordResp = mustHex("1241043836ef177c9e8db90adc161d578c0a1a93224fadd28a3db0dccbcee7e3068fcb517d689b93ef00326db9d7d9df79ec8ff7546c27619fc8b6f4b58013518faddd22d0020a41043623463352502aa3693fca6e814794cd367eb8d083b04d8c1039a736789557e0796440fff74726a1b102e0601eab526eba48c5bc188cf920b54886602ff7fbbf124104d081c0340b088b91db69f50a6ed7c36162eeb94903658169e0d73887886850558a5f82769b7a19ee39d8a18fcd5a547123411e8dfdae9c89796597aa54a6765f1a41043b482c5ceaa0a800c4048db7b8f1c797b2012a0402008afa4cf49af363f6d4b2b4d861d2f6c83895f33f61ab05d5f67579c5d06f9c4789dfb05f02346246a7af224104d373e5a27ff3153e96b01924479bc50cae80f0e55a35ccfdbc92a839ace4005fe7d9b96d5be40d490043ed021b29b7d14bae0d6e07a4707538e64773403665cb2a207b82d53e1e651d38fd82e2429b2ad2fa29e39b7be16da861e5a91f59669d7c1432200016177967123700ca26d131a734a27b8323e39e10ed17807107e4db3e9b9a55")
)

func getServerKeypair() []byte {
	res, _ := marshalKeypair(serverPublic, serverPrivate)
	return res
}

func mustHex(s string) []byte {
	res, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return res
}

func TestGetEnrollment(t *testing.T) {
	MockRandom()
	resp, err := GetEnrollment(getServerKeypair())
	require.NoError(t, err)
	require.Equal(t, enrollmentResponse, resp)
	EndMock()
}

func TestEnroll(t *testing.T) {
	MockRandom()
	cli, err := NewClient(clientPrivate, serverPublic)
	require.NoError(t, err)
	rec, key, err := cli.EnrollAccount(password, enrollmentResponse)
	require.NoError(t, err)
	require.Equal(t, enrollmentRecord, rec)
	require.Equal(t, recordKey, key)
	EndMock()
}

func TestValidPasswordRequest(t *testing.T) {
	cli, err := NewClient(clientPrivate, serverPublic)
	require.NoError(t, err)
	req, err := cli.CreateVerifyPasswordRequest(password, enrollmentRecord)
	require.NoError(t, err)
	require.Equal(t, req, verifyPasswordReq)
}

func TestVerifyValidPasswordResponse(t *testing.T) {
	MockRandom()
	resp, err := VerifyPassword(getServerKeypair(), verifyPasswordReq)
	require.NoError(t, err)
	require.Equal(t, resp, verifyPasswordResp)
	EndMock()
}

func TestInvalidPasswordRequest(t *testing.T) {
	cli, err := NewClient(clientPrivate, serverPublic)
	require.NoError(t, err)
	req, err := cli.CreateVerifyPasswordRequest(badPassword, enrollmentRecord)
	require.NoError(t, err)
	require.Equal(t, req, verifyBadPasswordReq)
}

func TestVerifyInvalidPasswordResponse(t *testing.T) {
	MockRandom()
	resp, err := VerifyPassword(getServerKeypair(), verifyBadPasswordReq)
	require.NoError(t, err)
	fmt.Println(hex.EncodeToString(resp))
	require.Equal(t, resp, verifyBadPasswordResp)

	EndMock()
}

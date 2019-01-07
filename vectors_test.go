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
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	serverPublic          = mustHex("04464173c0589a4dd70760f0fd8ddccf99ec829098d194e9c925403a35245d44f2acf6784fe4d7a5eb76ba0d23227625e0f264051c8ed36fe9088f210faa160a45")
	serverPrivate         = mustHex("403cde159ac7bafa8e04a88e3dcbaae06c3c2f46699c0a28344e5e54e3c460ca")
	clientPrivate         = mustHex("f587c094be766cf7d33120717bdf7e448cfea9c7ea69d4cae49f145e1f967b6c")
	enrollmentResponse    = mustHex("0a20fc9e1d89fa8b15e391f62b3de357b0f56fe4dec54a008c7556c477bc9679f83d124104a623af89752c65f091ee3a1bad2101fa1fd07af69630ff1b4362d48f6209ec2d46583eefe98e92b5101eac9627da22cf70ef1f0ca5f5bcb9a2b2868ee746e5e71a410446bfd5f5087e274ff9047d0afdf78f41f7984338e0285ab009eda24c347e5708346c30dfff0581c5086d9d9e348a54a361f5f0ed3f0f8627fe52c8694e592c9622eb010a4104eba8f5f434ab5e9e1d29b01dd6c90a4921b01bc3c27f508f4c750c1a3156ee32e89e336f96f5883cd03441b03d5543c3d869a71b8ed8ae43c12fe03cd67aeefd124104df22dc8b1ce0d11fe23e2b7a5efaa7e1881cf7d0a66bf25ad5979bc8b0b33876c20fbdb2dcf90f4bcb168bbb1cd5ece1217cad813a4b4a9774503b4ffbf6b9e21a4104e6dcadc5be875aafeb95e97bfd52b02560d30be3d1ba12662e44a408310a900bc14e79a70912329e0e58a5db5e6b54f2d674751a90544c1b171cde64481fc77c2220f09dbd69f7886dbba4b5527b52479cde3de8b2737641727d5e2476846e26ec2d")
	password              = mustHex("7061737377307264")
	enrollmentRecord      = mustHex("0a20fc9e1d89fa8b15e391f62b3de357b0f56fe4dec54a008c7556c477bc9679f83d1220fc9e1d89fa8b15e391f62b3de357b0f56fe4dec54a008c7556c477bc9679f83d1a41041cc2fc1243a1e6af99c6099c2bde1c1bc866a6072975f87c6bfce11db719b09f4832ac49db8ea7dc811f3239fee5b531a530e9a9915eb7be7ac51decb3cf7753224104bf0d5ccbc453fb0149c1c9789511ec6f0a85e07a1f9e3943b7826f23f53dfe61aa040abc0e41686702690ea496344a528be4e862da1786482db29631e634068c")
	recordKey             = mustHex("ffa2b491260f2b4ae5cf0849371fc521c3aa06a7f359bd1d30ad4b7de38ba316")
	verifyPasswordReq     = mustHex("0a20fc9e1d89fa8b15e391f62b3de357b0f56fe4dec54a008c7556c477bc9679f83d124104a623af89752c65f091ee3a1bad2101fa1fd07af69630ff1b4362d48f6209ec2d46583eefe98e92b5101eac9627da22cf70ef1f0ca5f5bcb9a2b2868ee746e5e7")
	verifyPasswordResp    = mustHex("080112410446bfd5f5087e274ff9047d0afdf78f41f7984338e0285ab009eda24c347e5708346c30dfff0581c5086d9d9e348a54a361f5f0ed3f0f8627fe52c8694e592c961aeb010a4104684ab1bdffa84453ebd6a1ec23cc7b4ae2ce6ebbe5a21b16856fd3847dad4559a312525ba0ab53d24a41fa5192ccdc742767d61a04318cd7b5b332d6741287af12410461c82f541a04b37e40545b4756325e4de1e8ba542d97dda356016694d87ae4cc6b3f25844d6504c1316e5c5442ce098d04a103257ac15b9ff16d4994d2af59cd1a410401d217f6d2ca53a85562cf36d13cf17f4db5c2737d8027afdad2bbfc8dcf0d9986c06e144c7ac5032d9fac36815be395ad9f343c3229a78e8a5e9c806181230e2220f90282dccb78ac4f14487ac00df7c736eee55e6d63e53d4e0e7679a2e1b3c8a1")
	badPassword           = mustHex("7040737377307264")
	verifyBadPasswordReq  = mustHex("0a20fc9e1d89fa8b15e391f62b3de357b0f56fe4dec54a008c7556c477bc9679f83d1241045950d1b2c56d8a77645fc784ddaa080066c20e19cbcc4805df27cfde4c88b744b01531b76d6be98f514870a2e4d2f7fa5139e20c7b517c7e8e56120f6dd0f6d3")
	verifyBadPasswordResp = mustHex("1241041a83e2221aa9796f5a5022c35f8bc764503c0cfb992bbd4eefb22bcd3186d280cf2783030316a538919abe2d697370a31bfba5133c2d679a22aed3327fc1da4722d0020a4104434fd3eb8d9df8ffc12667f09696ead6194ad7a197817bca53670852a4e32c0197dfeb50367622a88969d448daf8a1adf1416b884d2a6ae430820bd8bc36b9e3124104a773a99986143acf4698a2bcf93fa1ad02a8565f0231604d5f655ff70999ff55e4e5b6ef498d52342abf3b3ff72164017e52471abb06011392112058e36a14351a41049afb7fc9904b4fa45ab9993f91af369a6854b0f44d9048792be7327c2f9878172d0d64f9991fbcf6054bd463bf05e16b2e52d07671ad6e9f8c146605b21f61e3224104ea343565b7b2a6b8248e09ed2a3e4c32dbd7af391369be67387d6ccc4ab5baff7486ce95bf34cbaaec2a37ca380c33b10014450ffeec70dfde4a5eeaac5090cc2a2077e964767b16707315626307386c2a9d139dfa54de87a70e998124311d76a1743220f7dff81df7cc0582277944a89a75979766c89ba8e0ff5040fa85707c350521fe")
	token                 = mustHex("0a20fc9e1d89fa8b15e391f62b3de357b0f56fe4dec54a008c7556c477bc9679f83d122080390531494470be0b296501586bfcd9e131c39e2decc753d4f25fefd2281eea")
	rotatedServerPub      = mustHex("04c3b315ac3bbc101d7f71d31899fa44aecef0b1b879fab84c7f623d1113e6f7228b3399c246b345c6df0fa7af07cf39b558b13af502910d6c3b42d690468c2f1b")
	rotatedServerSk       = mustHex("001e0d5c37a3627a53fed34b9f3a4236d3f5b6faa72696998a1239903a4bd12b")
	rotatedClientSk       = mustHex("ceb6e27585f969f5d5c5bfb8bdc8337f369f381cc5e32efdc123ab74b06a441e")
	updatedRecord         = mustHex("0a20fc9e1d89fa8b15e391f62b3de357b0f56fe4dec54a008c7556c477bc9679f83d1220fc9e1d89fa8b15e391f62b3de357b0f56fe4dec54a008c7556c477bc9679f83d1a4104b1dba4fc25dbe850c14278188adad7f39eb8977db5b364d2fb851f2238bf03ab473cdae0c20de7d528ba8de5043c2eb3eed3d9d45b2e99290ef97af147692aa02241044971b0118442b7dd7fc3b0d098a3afb4c33c62768da00814224eeea77e9bf539fa0bc4279e2fcaff63aac3cbae33050c4d6626fdf04373c2bbbdc7bc609f3a1f")
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
	//fmt.Println(hex.EncodeToString(resp))
	require.Equal(t, enrollmentResponse, resp)
	EndMock()
}

func TestEnroll(t *testing.T) {
	MockRandom()
	cli, err := NewClient(clientPrivate, serverPublic)
	require.NoError(t, err)
	rec, key, err := cli.EnrollAccount(password, enrollmentResponse)
	require.NoError(t, err)
	//fmt.Println(hex.EncodeToString(rec))
	//fmt.Println(hex.EncodeToString(key))
	require.Equal(t, enrollmentRecord, rec)
	require.Equal(t, recordKey, key)
	EndMock()
}

func TestValidPasswordRequest(t *testing.T) {
	cli, err := NewClient(clientPrivate, serverPublic)
	require.NoError(t, err)
	req, err := cli.CreateVerifyPasswordRequest(password, enrollmentRecord)
	require.NoError(t, err)
	//fmt.Println(hex.EncodeToString(req))
	require.Equal(t, verifyPasswordReq, req)
}

func TestVerifyValidPasswordResponse(t *testing.T) {
	MockRandom()
	resp, err := VerifyPassword(getServerKeypair(), verifyPasswordReq)
	require.NoError(t, err)
	//fmt.Println(hex.EncodeToString(resp))
	require.Equal(t, verifyPasswordResp, resp)
	EndMock()
}

func TestInvalidPasswordRequest(t *testing.T) {
	cli, err := NewClient(clientPrivate, serverPublic)
	require.NoError(t, err)
	req, err := cli.CreateVerifyPasswordRequest(badPassword, enrollmentRecord)
	require.NoError(t, err)
	//fmt.Println(hex.EncodeToString(req))
	require.Equal(t, verifyBadPasswordReq, req)
}

func TestVerifyInvalidPasswordResponse(t *testing.T) {
	MockRandom()
	resp, err := VerifyPassword(getServerKeypair(), verifyBadPasswordReq)
	require.NoError(t, err)
	//fmt.Println(hex.EncodeToString(resp))
	require.Equal(t, verifyBadPasswordResp, resp)

	EndMock()
}

func TestRotateServerKeys(t *testing.T) {
	MockRandom()
	tkn, newKeypair, err := Rotate(getServerKeypair())
	require.NoError(t, err)
	kp, err := unmarshalKeypair(newKeypair)
	require.NoError(t, err)
	//fmt.Println(hex.EncodeToString(tkn))
	//fmt.Println(hex.EncodeToString(kp.PrivateKey))
	//fmt.Println(hex.EncodeToString(kp.PublicKey))
	require.Equal(t, token, tkn)
	require.Equal(t, rotatedServerSk, kp.PrivateKey)
	require.Equal(t, rotatedServerPub, kp.PublicKey)

	EndMock()
}

func TestRotateClientKey(t *testing.T) {
	cli, err := NewClient(clientPrivate, serverPublic)
	require.NoError(t, err)
	err = cli.Rotate(token)
	require.NoError(t, err)
	//fmt.Println(hex.EncodeToString(cli.clientPrivateKeyBytes))
	require.Equal(t, rotatedClientSk, cli.clientPrivateKeyBytes)
}

func TestRotateEnrollmentRecord(t *testing.T) {
	updrec, err := UpdateRecord(enrollmentRecord, token)
	require.NoError(t, err)
	//fmt.Println(hex.EncodeToString(updrec))
	require.Equal(t, updatedRecord, updrec)
}

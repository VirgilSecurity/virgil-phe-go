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
	enrollmentResponse    = mustHex("0a20fc9e1d89fa8b15e391f62b3de357b0f56fe4dec54a008c7556c477bc9679f83d12410431f28e769c06ae156d871d73e73faf7cf379ee0084942efbcd423a332bfd2df39490649da82b4aad66bde03de9b9628cbcbc1e929c909443b2cd0d785337c2251a4104abdd407edb3f496629d73baa4902024490ec92a204d840dd28f4da7d359a28916f461c38e4518b1e5e3b6ed4c2a1199fd4cff3d042904f716e6192bc3341098b22eb010a4104902de55082da233162075273e49b960c2b9decd9e86d33815663d89d5389e1977cb35d12ea7a7e2cabef4ee64661cbf63c0ad5138cd88a9bab06cc5e84b0b4ef12410423071685e0560e7ca649062b9d186b1a1c1201ebd35e2f13129612e3a8290b287e93ade625138fc0b6582311d155c15be1c9aa4b72d33dd3886cf121bf40dc8c1a4104e6dcadc5be875aafeb95e97bfd52b02560d30be3d1ba12662e44a408310a900bc14e79a70912329e0e58a5db5e6b54f2d674751a90544c1b171cde64481fc77c2220e54a9d8c42c190cc05215939af3a4a6e5d1a47024d2797499e492005e8e6f6d3")
	password              = mustHex("7061737377307264")
	enrollmentRecord      = mustHex("0a20fc9e1d89fa8b15e391f62b3de357b0f56fe4dec54a008c7556c477bc9679f83d1220fc9e1d89fa8b15e391f62b3de357b0f56fe4dec54a008c7556c477bc9679f83d1a410470545cf23ae7f9d3f774ecf787f3ee041c1f354957ad30b49bade5ae42885038691c709bc120d27d4e7915c6007c00e66c91c3efdcc6e43b2bb4bd1fd8bd4343224104e4d923005d3ae3e7913ce55f1633040e66b1319946fbdf40869cc6ad0fc28177f7eb9a35169cd16aabbb96c4eb3bd97ff55b9ba00cc1ea0f395e0b13f619466e")
	recordKey             = mustHex("5c3323db2181f99b326bb8157601df668a95c75fbe384214e81d7be91da37654")
	verifyPasswordReq     = mustHex("0a20fc9e1d89fa8b15e391f62b3de357b0f56fe4dec54a008c7556c477bc9679f83d12410431f28e769c06ae156d871d73e73faf7cf379ee0084942efbcd423a332bfd2df39490649da82b4aad66bde03de9b9628cbcbc1e929c909443b2cd0d785337c225")
	verifyPasswordResp    = mustHex("0801124104abdd407edb3f496629d73baa4902024490ec92a204d840dd28f4da7d359a28916f461c38e4518b1e5e3b6ed4c2a1199fd4cff3d042904f716e6192bc3341098b1aeb010a41045769f4bec1a27ca53685cffc2c77a357bd2042b68cdb4fd8d8af9f9d59b5885744f40719baee3b053d4d6382a5b75913a6a31685704c58f13c187646ed342e6a1241046b5be88750a786987e435ef73cb0f83d55ae7c07f2a2444ab31cb51f0fa04996791a9b9cf867ff2dd3be05884de7abffa42bacd05096e9539bd4255abfbc83431a410401d217f6d2ca53a85562cf36d13cf17f4db5c2737d8027afdad2bbfc8dcf0d9986c06e144c7ac5032d9fac36815be395ad9f343c3229a78e8a5e9c806181230e222031cd2f9fc0d44495fa7b41b09c1a950e18634f87879c0d1ffde4e4f305f8a506")
	badPassword           = mustHex("7040737377307264")
	verifyBadPasswordReq  = mustHex("0a20fc9e1d89fa8b15e391f62b3de357b0f56fe4dec54a008c7556c477bc9679f83d124104c266ca64e8dc70dc6f4e33ef7d98894a2f04b865cfda2fb813ba9085d35bf08c338c1a523fa1088bef6e39beb3872dcdf0d1782f7a9379e25c1ef00b0c162485")
	verifyBadPasswordResp = mustHex("1241040d2ccb01454a80ccc32d683c879b727b1a232433f217ac4fff761097b03aed0242de7a963f26d074217fb6541115c12cc0f1e2406d6cdf89544bbd5fba037eb022d0020a4104f50e905af176255a747eafe028a2807c236518717dddbfb2fb17881b56f2bcaedf8389cfdbea154cb81cdb8e9f0bc7c110c2c746c57e7fe2b7ec8fdafebf47d61241048cbd873f320a97fb2125591813f93e2c9da7d24c5b807f6be44b30f767cd88a776f2bab97217fa16e0d26ee748d409d0267aad0ab728ed1e36963eff5403195d1a41049afb7fc9904b4fa45ab9993f91af369a6854b0f44d9048792be7327c2f9878172d0d64f9991fbcf6054bd463bf05e16b2e52d07671ad6e9f8c146605b21f61e3224104ea343565b7b2a6b8248e09ed2a3e4c32dbd7af391369be67387d6ccc4ab5baff7486ce95bf34cbaaec2a37ca380c33b10014450ffeec70dfde4a5eeaac5090cc2a20216a54dd98dfcc6011899a20564168ef33e3f14eb47b2529a7ded388003e0e8a3220a544c943a039ba14317c396926df441e7fc0b5a0a5060ccb17be66b9759a03ea")
	token                 = mustHex("0a20fc9e1d89fa8b15e391f62b3de357b0f56fe4dec54a008c7556c477bc9679f83d122080390531494470be0b296501586bfcd9e131c39e2decc753d4f25fefd2281eea")
	rotatedServerPub      = mustHex("04c3b315ac3bbc101d7f71d31899fa44aecef0b1b879fab84c7f623d1113e6f7228b3399c246b345c6df0fa7af07cf39b558b13af502910d6c3b42d690468c2f1b")
	rotatedServerSk       = mustHex("1e0d5c37a3627a53fed34b9f3a4236d3f5b6faa72696998a1239903a4bd12b")
	rotatedClientSk       = mustHex("ceb6e27585f969f5d5c5bfb8bdc8337f369f381cc5e32efdc123ab74b06a441e")
	updatedRecord         = mustHex("0a20fc9e1d89fa8b15e391f62b3de357b0f56fe4dec54a008c7556c477bc9679f83d1220fc9e1d89fa8b15e391f62b3de357b0f56fe4dec54a008c7556c477bc9679f83d1a4104da044d90262872d9153176f85574a090ab64ec73d9ce4d4f7f885b8226660291e16314f0230b492364c682678774ae2c0083864ce11d1e8daa6b07313b7c6f4c22410400b5fcdd1e0b2142cd317a12ee1462c4e3192d0d1543cff6eb684dfc3dff3bc8354c386288a5154d2962e0c9fa025c384159ba8467cf15bf19965df8a6e1be13")
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

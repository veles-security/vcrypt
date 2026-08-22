package rsa

import (
	"context"
	stdrsa "crypto/rsa"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/veles-security/vcrypt/internal/testkeys"
	"github.com/veles-security/vcrypt/key"
	"github.com/veles-security/vcrypt/material"
)

func Test_joseDecoder_Decode(t *testing.T) {
	// keys
	privateKey := testkeys.Private(t, testkeys.RSA2048).(*stdrsa.PrivateKey)
	// JSON Web Keys
	publicEncryptionJWK := []byte(`{
		"kty":"RSA", "kid":"payments-api-encryption-2026-08", "use":"enc",
		"key_ops":["encrypt","wrapKey"], "alg":"RSA-OAEP-256",
		"n":"x457suHRD7n8qToSDmZjxRLT2qdJpWy3qKfUmh10t-kcRgsgBMeaA9vbAgpZu8CG33ory3nZGt9gw3Q0OKJ9SMwe0SLzOgpzzPM7dhniJc2DxxLaBSAqvlQ2STaa7JABwfiNNcrTA0QLQ8kwdpVoWwiR7kYXlPwgIEMghsSE7GyLUzsIxAND7bq2z5t3RwLiZgaS5WWbb5ltc-mreO7vE0NtUlDTx3UWn8FxlmiNbi6DaCThezYsENZRI0yOIjxitFQ1wxJd7U0GgAS_LmrQQBjV8fGGfYOzazuKwIcEt0PQn54ULM9RQypjVPpfgJdUMlkLqxK2nWu09Mhr-CGNkQ",
		"e":"AQAB"
	}`)
	privateSigningJWK := []byte(`{
		"kty":"RSA","kid":"prod-signing-2026-08","use":"sig","key_ops":["sign","verify"],"alg":"RS256",
		"n":"x457suHRD7n8qToSDmZjxRLT2qdJpWy3qKfUmh10t-kcRgsgBMeaA9vbAgpZu8CG33ory3nZGt9gw3Q0OKJ9SMwe0SLzOgpzzPM7dhniJc2DxxLaBSAqvlQ2STaa7JABwfiNNcrTA0QLQ8kwdpVoWwiR7kYXlPwgIEMghsSE7GyLUzsIxAND7bq2z5t3RwLiZgaS5WWbb5ltc-mreO7vE0NtUlDTx3UWn8FxlmiNbi6DaCThezYsENZRI0yOIjxitFQ1wxJd7U0GgAS_LmrQQBjV8fGGfYOzazuKwIcEt0PQn54ULM9RQypjVPpfgJdUMlkLqxK2nWu09Mhr-CGNkQ","e":"AQAB",
		"d":"LZ_sNLMP6RxRAcDi4XNz8poSIU73ldCEMhWDFGRRK_4qRnJjNOyM0D6LNU14BCbpvzzvt-MJKe1x8mYGTX-LDOKMViz7NqUuoihnSyJyU8nHy_NJsPvQgfj_e2A2bgkjub0xzd9sPLYpLCuavrX8qLmOIc_ZMuktECtAy8cxC9uCR1EMZO5qNGQ_Oy_SH4WEkRUCqoQN73ynWNV0ze2uitqnKd4xK6Al72TCsIYkSZqcSkYHNFf9OBB59TM_VVTvQ9uEddcyop3igAUd_0zJns_jiOtjK2fsRIHFURwgvjvzMunsH32NhmoihkHo309xKH-x4GzyfcFlcFoqq5S15Q",
		"p":"ylJbT_ScVDwz-Po9HoCo3OZvPyeBL3fd56lrIOjLdcrgRCZjakeuCrE0A0kF3hMSAKHrXOUlh_W0b1VroC744PGqKXu2KWW4fmUOwyEvfaAirvnIkDimJyeEvp_ZT6e10AAodQkNYRKqPXDk6YKFuzWlYL0DgpB4CMnuUZazyV0",
		"q":"_IBRyIDUpGTT2V8jY5rwqPNYnJr2TnX9jRYp4_EcKFQMhYeIMuksv9VxRNCK78V35IiM4HoKwQ5PlIrCofQ7pEsIhge3Fxc7ZXQ1Iqcc8ClJqbRCtTQiGE3pyoT4Lx6e2pSvaEfZ7PGewLxZX0yxkQ-D3qlqBnfY4BkJ8x-HbcU",
		"dp":"wB8umKFmpdK5Y690xHdWYtXrQ-Rml0XTEb5efVSyh_uLtQtjEjRY_8w_4PLBwJ0JVlJr5r2uQwo-Og66cdTI_wpdFKFmXK88X8HlH8RujXO4G8IUA2fX14x-UGoIeMyAKLFNub1L2CdaQ5fluBv6k8igb1ltcNlxMp9WUGGz_f0",
		"dq":"UpLELAW1hG1UumlacWBiA15RRCWJFu-PE2yEFn7q7mVOEvzXlY6bi8CJYi-wv-ib5KijKWW_zpKXg8Q9EimEt52yE-LCBVMboXn3RnXQCNn3tP-2MPvzim8wXYJOh1pEKMcm9btJkSsS94Sg1YGHMCEaxt4wRh07V03Y6yEMcOE",
		"qi":"Ek2tn7HoMOmSod0YOiw4_snoj03CtNr3srFttfSH53TNdBG81VYq3nsdBiOcbI7JlLBQ6QgR7R-uA05UbAs-GNE6Eym0wpSD1T1xjQKTIUBS4_8PxqCeON8SSb9vI-Nxn7BWF2uI4jT2rjUMgXbZlmuC1kmikt6E2lIk-3guDgA"
	}`)
	// contexts
	canceledContext, cancel := context.WithCancel(context.Background())
	cancel()

	// assertions
	assertPublicEncryptionKey := func(t *testing.T, candidate key.KeyCandidate, err error) {
		if err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		if candidate.ID != "payments-api-encryption-2026-08" {
			t.Errorf("Decode() ID = %q, want %q", candidate.ID, "payments-api-encryption-2026-08")
		}
		publicMaterial, ok := candidate.Material.(*material.PublicMaterial)
		if !ok {
			t.Fatalf("Decode() material = %T, want *material.PublicMaterial", candidate.Material)
		}
		publicKey, ok := publicMaterial.Key.(*stdrsa.PublicKey)
		if !ok || !publicKey.Equal(&privateKey.PublicKey) {
			t.Errorf("Decode() public key does not match fixture key")
		}
		want := []key.Capability{
			{Use: key.KeyUseEncryption, Operation: key.KeyOpEncrypt, Algorithm: RSAOAEP256},
			{Use: key.KeyUseEncryption, Operation: key.KeyOperation("wrapKey"), Algorithm: RSAOAEP256},
		}
		if !reflect.DeepEqual(candidate.Restrictions, want) {
			t.Errorf("Decode() restrictions = %#v, want %#v", candidate.Restrictions, want)
		}
	}
	assertPrivateSigningKey := func(t *testing.T, candidate key.KeyCandidate, err error) {
		if err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		if candidate.ID != "prod-signing-2026-08" {
			t.Errorf("Decode() ID = %q, want %q", candidate.ID, "prod-signing-2026-08")
		}
		privateMaterial, ok := candidate.Material.(*material.PrivateMaterial)
		if !ok {
			t.Fatalf("Decode() material = %T, want *material.PrivateMaterial", candidate.Material)
		}
		decoded, ok := privateMaterial.Key.(*stdrsa.PrivateKey)
		if !ok || !decoded.Equal(privateKey) {
			t.Errorf("Decode() private key does not match fixture key")
		}
		want := []key.Capability{
			{Use: key.KeyUseSigning, Operation: key.KeyOpSign, Algorithm: RS256},
			{Use: key.KeyUseSigning, Operation: key.KeyOpVerify, Algorithm: RS256},
		}
		if !reflect.DeepEqual(candidate.Restrictions, want) {
			t.Errorf("Decode() restrictions = %#v, want %#v", candidate.Restrictions, want)
		}
	}
	assertErrorContaining := func(want string) func(*testing.T, key.KeyCandidate, error) {
		return func(t *testing.T, candidate key.KeyCandidate, err error) {
			if err == nil {
				t.Fatalf("Decode() error = nil, want error containing %q", want)
			}
			if !strings.Contains(err.Error(), want) {
				t.Errorf("Decode() error = %q, want error containing %q", err, want)
			}
			if !reflect.DeepEqual(candidate, key.KeyCandidate{}) {
				t.Errorf("Decode() candidate = %#v, want zero value", candidate)
			}
		}
	}
	assertCanceled := func(t *testing.T, candidate key.KeyCandidate, err error) {
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Decode() error = %v, want context.Canceled", err)
		}
		if !reflect.DeepEqual(candidate, key.KeyCandidate{}) {
			t.Errorf("Decode() candidate = %#v, want zero value", candidate)
		}
	}
	tests := []struct {
		name      string
		ctx       context.Context
		encoded   []byte
		options   []key.JOSEDecodeOption
		assertion func(*testing.T, key.KeyCandidate, error)
	}{
		{name: "OIDC Public Encryption JWK", ctx: context.Background(), encoded: publicEncryptionJWK, assertion: assertPublicEncryptionKey},
		{name: "Service Private Signing JWK", ctx: context.Background(), encoded: privateSigningJWK, assertion: assertPrivateSigningKey},
		{name: "Canceled Context", ctx: canceledContext, encoded: publicEncryptionJWK, assertion: assertCanceled},
		{name: "Too Many Options", ctx: context.Background(), encoded: publicEncryptionJWK, options: []key.JOSEDecodeOption{{}, {}}, assertion: assertErrorContaining("expected at most one option")},
		{name: "Malformed JSON", ctx: context.Background(), encoded: []byte(`{"kty":"RSA"`), assertion: assertErrorContaining("unmarshal JWK")},
		{name: "Unsupported Key Type", ctx: context.Background(), encoded: []byte(`{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}`), assertion: assertErrorContaining(`unsupported kty "EC"`)},
		{name: "Missing Modulus", ctx: context.Background(), encoded: []byte(`{"kty":"RSA","e":"AQAB"}`), assertion: assertErrorContaining(`parameter "n" is missing`)},
		{name: "Invalid Modulus Encoding", ctx: context.Background(), encoded: []byte(`{"kty":"RSA","n":"%%%","e":"AQAB"}`), assertion: assertErrorContaining(`decode parameter "n"`)},
		{name: "Invalid Exponent", ctx: context.Background(), encoded: []byte(`{"kty":"RSA","n":"AQ","e":"AQ"}`), assertion: assertErrorContaining("invalid exponent")},
		{name: "Incomplete Private Key", ctx: context.Background(), encoded: []byte(`{"kty":"RSA","n":"AQ","e":"Aw","d":"AQ"}`), assertion: assertErrorContaining("private JWK parameters")},
	}
	decoder := &joseDecoder{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := decoder.Decode(tt.ctx, tt.encoded, tt.options...)
			tt.assertion(t, got, gotErr)
		})
	}
}

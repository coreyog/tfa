package tfa

import (
	"encoding/base32"
	"net/url"
	"testing"
)

func TestProperSecretGeneration(t *testing.T) {
	t.Parallel()

	when := uint64(1494475275)

	testcases := []struct {
		Secret string
		Code   string
		When   uint64
		Name   string
		Issuer string
	}{
		{"V2YJQHDQUJTN4BVBX3XZSKF7HJYM6OYFL3FUWERM3UF4RVFFFJ6Q====", "383561", when, "test", "test"},
		{"6Q7D47BGVIMUPVUECDLU7OOTYD4LTGUN7U4KLDOHRXQ3B4ITFYXQ====", "432649", when, "Github", "Github"},
		{"UADGUPDFCHJ32F6TAPWRV7AUVKOGM3NKUBFYXBJNSIN3PRD77R2Q====", "678895", when, "Google", "Google"},
		{"FGQXKDZT2PTFG6BJJNTSCAPP55RYOH52JTABEJGFSA6IKYFFM3BA====", "778285", when, "Twitter", "Twitter"},
		{"QGKPUVKGLEBBRNCHX2WHUWSJZ3KSFKIZWEZA7DGMZXYWAAILXK2Q====", "103713", when, "My Bank", "corporate"},
		{"ZG4F2JV5LTFDH2DQDLIPRGYNAI3OKXSS3ZLWOZUEYFC53DHJYD7A====", "649000", when, "www.example.com", "www.example.com"},
		{"G4XXKUWWKJX4CAK6DCIINBE7ADV5DLTYQMQYHWF6FVOVLR4HYS3A====", "053682", when, "X", "X"},
		{"VE4ZK4JVZOEU544NRCBOTVINANSWUJTQ7EPIHIDFFINWVFC4LQKA====", "603745", when, "Y", "Y"},
		{"VSLKYV6IW7YAOWWBLGHXB5MXNBXUYXF2NP4BIRP6ZANOVE72DKHA====", "204418", when, "Z", "Z"},
		{"XZLJLLXIUWMVGKPCSSPZETJIBFISFT5XZLL7A6ZAHINKO7DCV5KQ====", "125527", when, "A", "A"},
	}

	for _, test := range testcases {
		test := test
		t.Run(test.Code, func(t *testing.T) {
			t.Parallel()

			secret, err := base32.StdEncoding.DecodeString(test.Secret)
			if err != nil {
				t.Error("error parsing secret:", err)
			}

			code := GenerateCode(secret, test.When)
			if code != test.Code {
				t.Errorf("Expected code: %s, Actual code: %s", test.Code, code)
			}

			u, err := url.Parse(GenerateQrUrl(secret, test.Issuer, test.Name))
			if err != nil {
				t.Error("unexpected error parsing QR URL:", err)
			}

			if u.Scheme != "otpauth" {
				t.Error("expected qr url scheme to be otpauth")
			}

			if u.Path != "/"+url.QueryEscape(test.Name) {
				t.Errorf("Qr Name error, expected: /%s, actual: %s", url.QueryEscape(test.Name), u.Path)
			}

			q := u.Query()

			if q.Get("issuer") != url.QueryEscape(test.Issuer) {
				t.Errorf("Qr Issuer error, expected: %s, actual: %s", url.QueryEscape(test.Issuer), q.Get("issuer"))
			}

			if q.Get("secret") != test.Secret {
				t.Errorf("Qr Secret error, expected: %s, actual: %s", test.Secret, q.Get("secret"))
			}
		})
	}
}

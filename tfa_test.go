package tfa

import (
	"encoding/base32"
	"testing"
)

func TestProperSecretGeneration(t *testing.T) {
	secrets := []string{
		"V2YJQHDQUJTN4BVBX3XZSKF7HJYM6OYFL3FUWERM3UF4RVFFFJ6Q====",
		"6Q7D47BGVIMUPVUECDLU7OOTYD4LTGUN7U4KLDOHRXQ3B4ITFYXQ====",
		"UADGUPDFCHJ32F6TAPWRV7AUVKOGM3NKUBFYXBJNSIN3PRD77R2Q====",
		"FGQXKDZT2PTFG6BJJNTSCAPP55RYOH52JTABEJGFSA6IKYFFM3BA====",
		"QGKPUVKGLEBBRNCHX2WHUWSJZ3KSFKIZWEZA7DGMZXYWAAILXK2Q====",
		"ZG4F2JV5LTFDH2DQDLIPRGYNAI3OKXSS3ZLWOZUEYFC53DHJYD7A====",
		"G4XXKUWWKJX4CAK6DCIINBE7ADV5DLTYQMQYHWF6FVOVLR4HYS3A====",
		"VE4ZK4JVZOEU544NRCBOTVINANSWUJTQ7EPIHIDFFINWVFC4LQKA====",
		"VSLKYV6IW7YAOWWBLGHXB5MXNBXUYXF2NP4BIRP6ZANOVE72DKHA====",
		"XZLJLLXIUWMVGKPCSSPZETJIBFISFT5XZLL7A6ZAHINKO7DCV5KQ====",
	}
	when := int64(1494475275)
	codes := []string{
		"383561",
		"432649",
		"678895",
		"778285",
		"103713",
		"649000",
		"053682",
		"603745",
		"204418",
		"125527",
	}
	for i := 0; i < len(secrets); i++ {
		secret, err := base32.StdEncoding.DecodeString(secrets[i])
		if err != nil {
			t.Error("error parsing secret:", err)
		}
		code := GenerateCode(secret, when)
		if code != codes[i] {
			t.Error("Expected code: 922417, Actual code:", code)
		}
	}
}
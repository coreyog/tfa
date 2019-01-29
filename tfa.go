package tfa

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"net/url"
	"strconv"
)

// GenerateCode produces the 6 digit string the user is prompted for using the current time
func GenerateCode(secret []byte, when int64) string {
	bunix := make([]byte, 8)
	binary.BigEndian.PutUint64(bunix, uint64(when)/30)
	hasher := hmac.New(sha1.New, secret)
	hasher.Write(bunix)
	hmac := hasher.Sum(nil)
	offset := hmac[len(hmac)-1] & 0x0F
	subHmac := hmac[offset : offset+4]
	subHmac[0] = subHmac[0] & 0x7F
	wholeNum := binary.BigEndian.Uint32(subHmac)
	lastSix := int(wholeNum % 1000000)
	code := strconv.Itoa(lastSix)
	for len(code) < 6 {
		code = "0" + code
	}
	return code
}

// GenerateQRURL produces the proper URL to be encoded to a QR image that can be scanned by Google Authenticator
func GenerateQRURL(secret []byte, issuer string, name string) string {
	qr := "otpauth://totp/"
	qr += url.QueryEscape(name)
	qr += "?secret="
	qr += base32.StdEncoding.EncodeToString(secret)
	qr += "&issuer="
	qr += url.QueryEscape(issuer)
	return qr
}

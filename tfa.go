package tfa

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// GenerateCode produces the 6 digit string the user is prompted for using the
// current time.
func GenerateCode(secret []byte, when uint64) string {
	// Encode the time as a big endian uint64 into a byte slice.
	bunix := make([]byte, 8)
	binary.BigEndian.PutUint64(bunix, when/30)

	// HMAC the secret and the timestamp together
	hasher := hmac.New(sha1.New, secret)
	hasher.Write(bunix)
	hmac := hasher.Sum(nil)

	// Use the last nibble of the last byte as the offset for picking 4 bytes
	// from the HMAC. Ensure the resulting uint32 is positive.
	offset := hmac[len(hmac)-1] & 0x0F
	subHmac := hmac[offset : offset+4]
	subHmac[0] &= 0x7F

	// Convert the 4 bytes to a uint32 and truncate to 6 digits.
	wholeNum := binary.BigEndian.Uint32(subHmac)
	lastSix := int(wholeNum % 1000000)

	// Pad the 6 digits with zeros.
	code := strconv.Itoa(lastSix)
	reqPadding := 6 - len(code)

	if reqPadding > 0 {
		code = strings.Repeat("0", reqPadding) + code
	}

	return code
}

// GenerateQrUrl produces the proper URL to be encoded to a QR image that can be
// scanned by Google Authenticator or similar.
func GenerateQrUrl(secret []byte, issuer string, name string) string {
	n := url.QueryEscape(name)
	s := base32.StdEncoding.EncodeToString(secret)
	i := url.QueryEscape(issuer)

	return fmt.Sprintf("otpauth://totp/%s?secret=%s&issuer=%s", n, s, i)
}

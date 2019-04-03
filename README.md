# Two Factor Authentication
For a user, Two Factor Authentication (TFA or 2FA) makes things pretty simple. The user loads a QR code into their Authenticator app and they get codes every 30 seconds that helps them sign into their accounts. No network required. The short of it is that there's a ~32 byte secret stored in that QR. It goes through a fun HMAC process with that secret and how many 30 second intervals have passed since January 1, 1970 then uses certain bits of that output as an offset to pick enough bits to use to create a 6 digit number. Easy right? Well, hopefully it is now.

What goes on behind the scenes is that when you create an account at a website and you turn on TFA, you get ~32 cryptographically secure random bytes generated and tied to your account. Those bytes, through QR code, are entered into your authenticator app which constantly displays the latest time sensitive code. The website you're signing into is doing the same thing when you submit your code. They take your stored secret and the current time and generate the code. If it matches the user input then the user must have the same secret stored in their device. Sometimes, because of possible timing related issues, the website will generate multiple codes before and after the current time just in case your device is slightly slower or faster than the server.

## Installation
Use the `go` tool:

  $ go get github.com/coreyog/tfa

## Examples
```go
package main

import (
  "crypto/rand"
  "encoding/base32"
  "fmt"
  "time"

  "github.com/coreyog/tfa"
)

func main() {
  secret := make([]byte, 32)
  rand.Read(secret)
  // Here's the value you store away
  b32secret := base32.StdEncoding.EncodeToString(secret)
  fmt.Printf("Secret to store in DB: %s\n", b32secret)

  // Generate the 6 digit code for this secret
  code := tfa.GenerateCode(secret, time.Now().Unix())
  fmt.Printf("Code you check against user input: %s\n", code)
}
```
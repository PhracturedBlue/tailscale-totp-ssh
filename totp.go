// TOTP handler
 package main

import (
	"fmt"
	"log"
	"encoding/base64"
	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"
)

// Validate TSRP key if specified, or generate a new one and return it
// If a new key is generated, the UR, the encypted-key, and the QR code for the client is also displayed
// The key is encrypted to make casual snooping harder to extract...Ths is just security through obscurity
func initializeTOTP(key *[32]byte) string {
	if (*configTOTP == "") {
		totpKey, err := totp.Generate(totp.GenerateOpts{
			Issuer:      "SSH",
			AccountName: "foo@example.com",
			Period:      30, // Time step in seconds
			SecretSize:  20, // Length of the secret key
			Digits:      6,  // Number of digits in the OTP code
			Algorithm:   0,  // Hashing algorithm (SHA1 by default)
		})
		if err != nil {
			panic(err)
		}
		enc, err := Encrypt([]byte(totpKey.Secret()), key)
		if err != nil {
			panic(err)
		}
		log.Printf("Secret key: %s", base64.StdEncoding.EncodeToString(enc))
		fmt.Println("Provisioning URI:", totpKey.URL())
		q, err := qrcode.New(totpKey.URL(), qrcode.Low)
		if err != nil {
			panic(err)
		}
		art := q.ToString(false)
		fmt.Println(art)
		return totpKey.Secret()
	} else {
		decodedData, err := base64.StdEncoding.DecodeString(*configTOTP)
		if err != nil {
			panic(err)
		}
		sec, err := Decrypt(decodedData, key)
		if err != nil {
			panic(err)
		}
		secret := string(sec)
		log.Printf("Secret: %s", secret)
		return secret
	}
}

func validateTOTP(pass, secret string) bool {
	return totp.Validate(pass, secret)
}

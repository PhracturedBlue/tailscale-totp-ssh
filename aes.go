// Encryption Routines

package main

import (
	"io"
	"errors"
	"log"

	"encoding/base64"
	"crypto/aes"
	// crypto functions from https://github.com/gtank/cryptopasta/blob/master/encrypt.go
	"crypto/cipher"
	"crypto/rand"
)

var aeskey string

// Generate symmetric encryption key
func NewEncryptionKey() *[32]byte {
	key := [32]byte{}
	_, err := io.ReadFull(rand.Reader, key[:])
	if err != nil {
		panic(err)
	}
	return &key
}

// Encrypt byte data with encryption key
func Encrypt(plaintext []byte, key *[32]byte) (ciphertext []byte, err error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt byte data with encryption key
func Decrypt(ciphertext []byte, key *[32]byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("malformed ciphertext")
	}

	return gcm.Open(nil,
		ciphertext[:gcm.NonceSize()],
		ciphertext[gcm.NonceSize():],
		nil,
	)
}

// Detect if an encryption key was built into the binary, and exit with a new key if not
// otherwise return the provided key in the needed format
func initializeKey() *[32]byte {
	if aeskey == "" {
		_k := NewEncryptionKey()
		log.Fatalf("AESKEY was not supplied.  Rebuild with:\ngo build -ldflags '-s -w -X main.aeskey=%s'",
			base64.StdEncoding.EncodeToString(_k[:]))
	}
	_k, err := base64.StdEncoding.DecodeString(aeskey)
	if err != nil {
		panic(err)
	}
	key := [32]byte(_k)
	return &key
}


package dnscrypt

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDNSCryptResponseEncryptDecryptXSalsa20Poly1305(t *testing.T) {
	testDNSCryptResponseEncryptDecrypt(t, XSalsa20Poly1305)
}

func TestDNSCryptResponseEncryptDecryptXChacha20Poly1305(t *testing.T) {
	testDNSCryptResponseEncryptDecrypt(t, XChacha20Poly1305)
}

func testDNSCryptResponseEncryptDecrypt(t *testing.T, esVersion CryptoConstruction) {
	// Generate the secret/public pairs
	clientSecretKey, clientPublicKey := generateRandomKeyPair()
	serverSecretKey, serverPublicKey := generateRandomKeyPair()

	// Generate client shared key
	clientSharedKey, err := computeSharedKey(esVersion, &clientSecretKey, &serverPublicKey)
	assert.Nil(t, err)

	// Generate server shared key
	serverSharedKey, err := computeSharedKey(esVersion, &serverSecretKey, &clientPublicKey)
	assert.Nil(t, err)

	r1 := &EncryptedResponse{
		EsVersion: esVersion,
	}
	// Fill client-nonce
	_, _ = rand.Read(r1.Nonce[:nonceSize/12])

	// Generate random packet
	packet := make([]byte, 100)
	_, _ = rand.Read(packet[:])

	// Encrypt it
	encrypted, err := r1.Encrypt(packet, serverSharedKey)
	assert.Nil(t, err)

	// Now let's try decrypting it
	r2 := &EncryptedResponse{
		EsVersion: esVersion,
	}

	// Decrypt it
	decrypted, err := r2.Decrypt(encrypted, clientSharedKey)
	assert.Nil(t, err)

	// Check that packet is the same
	assert.True(t, bytes.Equal(packet, decrypted))
}

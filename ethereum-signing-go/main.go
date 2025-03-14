package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"io"

	"fmt"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

func generateKeyPair() (pubkey, privkey []byte) {
	key, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	pubkey = secp256k1.S256().Marshal(key.X, key.Y)

	privkey = make([]byte, 32)
	blob := key.D.Bytes()
	copy(privkey[32-len(blob):], blob)

	return pubkey, privkey
}

// csprngEntropy generates n bytes of cryptographically secure random data using Go's crypto/rand
// It uses a cryptographically secure pseudorandom number generator (CSPRNG) to generate entropy
// The function takes an integer n as input and returns a byte slice of length n filled with random bytes
// If reading from the random source fails, it panics with an error message
func csprngEntropy(n int) []byte {
	buf := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		panic("reading from crypto/rand failed: " + err.Error())
	}
	return buf
}

func main() {

	// randomString := "Hello Crypto folks!"

	pubkey, privkey := generateKeyPair()

	fmt.Println("Public Key:", hex.EncodeToString(pubkey))
	fmt.Println("Private Key:", hex.EncodeToString(privkey))

	msg := csprngEntropy(32)
	fmt.Println("Message:", hex.EncodeToString(msg))

	sign, err := secp256k1.Sign(msg, privkey)

	if err != nil {
		panic(err)
	}

	fmt.Println("Signaure :", hex.EncodeToString(sign))

}

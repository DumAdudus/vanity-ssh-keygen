package ed25519

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"io"

	"github.com/Mattias-/vanity-ssh-keygen/pkg/keygen/ed25519/edkey"
)

var ed25519BinaryHeader = []byte{0, 0, 0, 11, 's', 's', 'h', '-', 'e', 'd', '2', '5', '5', '1', '9', 0, 0, 0, 32}

type ed struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
	pubKeyBuf  [81]byte
}

func New() *ed {
	return &ed{}
}

func (s *ed) Generate() {
	s.publicKey, s.privateKey, _ = generateKey()
}

func (s *ed) SSHPubkey() []byte {
	return s.pubKeyBuf[:]
}

func (s *ed) SSHPrivkey() []byte {
	privDER := edkey.MarshalED25519PrivateKey(s.privateKey)
	b := pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: privDER,
	}
	// Private key in PEM format
	privatePEM := pem.EncodeToMemory(&b)
	return privatePEM
}

func generateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return nil, nil, err
	}

	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := ed25519.PublicKey(privateKey[32:])
	return publicKey, privateKey, nil
}

package ed25519

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"io"
	"sync"
	_ "unsafe"

	"github.com/Mattias-/vanity-ssh-keygen/pkg/keygen/ed25519/edkey"
	"golang.org/x/crypto/ssh"
)

var (
	seedPool = sync.Pool{
		New: func() any {
			seed := make([]byte, ed25519.SeedSize)
			return &seed
		},
	}
	privKeyPool = sync.Pool{
		New: func() any {
			privKey := make([]byte, ed25519.PrivateKeySize)
			return &privKey
		},
	}
)

type Ed struct {
	publicKey     ed25519.PublicKey
	privateKey    ed25519.PrivateKey
	authorizedKey []byte
	privKeyBuf    *[]byte
}

func New() *Ed {
	return &Ed{
		privKeyBuf: privKeyPool.Get().(*[]byte),
	}
}

func (s *Ed) Generate() {
	s.generateKey()
	s.updatePubkey()
}

func (s *Ed) SSHPubkey() []byte {
	return s.authorizedKey
}

func (s *Ed) SSHPrivkey() []byte {
	b, _ := ssh.MarshalPrivateKey(s.privateKey, "")
	privatePEM := pem.EncodeToMemory(b)
	return privatePEM
}

func (s *Ed) SSHPrivkeyOld() []byte {
	privDER := edkey.MarshalED25519PrivateKey(s.privateKey)
	b := pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: privDER,
	}
	// Private key in PEM format
	privatePEM := pem.EncodeToMemory(&b)
	return privatePEM
}

func (s *Ed) ReleaseBuf() {
	privKeyPool.Put(s.privKeyBuf)
}

func (s *Ed) updatePubkey() {
	publicKey, _ := ssh.NewPublicKey(s.publicKey)
	s.authorizedKey = ssh.MarshalAuthorizedKey(publicKey)
}

func (s *Ed) generateKey() {
	seedBuf := seedPool.Get().(*[]byte)
	defer seedPool.Put(seedBuf)
	seed := *seedBuf
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return
	}

	privateKey := *s.privKeyBuf
	newKeyFromSeed(privateKey, seed)
	publicKey := ed25519.PublicKey(privateKey[32:])
	s.publicKey, s.privateKey = publicKey, privateKey
}

//go:linkname newKeyFromSeed crypto/ed25519.newKeyFromSeed
func newKeyFromSeed(privateKey, seed []byte)

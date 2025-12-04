package ed25519

import (
	"bytes"
	"encoding/pem"
	"os"
	"testing"

	"github.com/Mattias-/vanity-ssh-keygen/pkg/keygen/ed25519/edkey"
	"golang.org/x/crypto/ssh"
)

func TestEd25519(t *testing.T) {
	e := New()
	e.Generate()

	pub := e.SSHPubkey()
	if len(pub) == 0 {
		t.Error("SSHPubkey() returned empty result")
	}

	_, _, _, _, err := ssh.ParseAuthorizedKey(pub)
	if err != nil {
		t.Errorf("Failed to parse authorized key: %v", err)
	}

	priv := e.SSHPrivkey()
	if len(priv) == 0 {
		t.Error("SSHPrivkey() returned empty result")
	}

	_, err = ssh.ParseRawPrivateKey(priv)
	if err != nil {
		t.Errorf("Failed to parse private key: %v", err)
	}
}

func TestSSHPrivPem(t *testing.T) {
	key := New()
	key.Generate()

	privDER := edkey.MarshalED25519PrivateKey(key.privateKey)
	b, _ := ssh.MarshalPrivateKey(key.privateKey, "")
	if !bytes.Equal(privDER, b.Bytes) {
		t.Errorf("pem der should be same\nself: %v\nxssh: %v\n", privDER, b.Bytes)
		os.WriteFile("self.pem", key.SSHPrivkey(), 0o600)
		os.WriteFile("xssh.pem", pem.EncodeToMemory(b), 0o600)
	}
}

func BenchmarkSSHPubkey(b *testing.B) {
	e := New()
	e.Generate()
	for i := 0; i < b.N; i++ {
		_ = e.SSHPubkey()
	}
}

func BenchmarkGenerate(b *testing.B) {
	e := New()
	for i := 0; i < b.N; i++ {
		e.Generate()
	}
}

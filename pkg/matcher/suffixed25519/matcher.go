package suffixed25519

import (
	"bytes"

	"github.com/Mattias-/vanity-ssh-keygen/pkg/keygen"
)

type suffixEd25519Matcher struct {
	suffix []byte
}

func New() *suffixEd25519Matcher {
	return &suffixEd25519Matcher{}
}

func (m *suffixEd25519Matcher) SetMatchString(matchString string) {
	m.suffix = []byte(matchString)
}

func (m *suffixEd25519Matcher) Match(s keygen.SSHKey) bool {
	pubK := s.SSHPubkey()
	return bytes.HasSuffix(keygen.EffectiveED25519PubKey(pubK), m.suffix)
}

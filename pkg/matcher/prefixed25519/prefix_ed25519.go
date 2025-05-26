package prefixed25519

import (
	"bytes"

	"github.com/Mattias-/vanity-ssh-keygen/pkg/keygen"
)

type prefixEd25519Matcher struct {
	prefix []byte
}

func New() *prefixEd25519Matcher {
	return &prefixEd25519Matcher{}
}

func (m *prefixEd25519Matcher) SetMatchString(matchString string) {
	m.prefix = []byte(matchString)
}

func (m *prefixEd25519Matcher) Match(s keygen.SSHKey) bool {
	pubK := s.SSHPubkey()
	return bytes.HasPrefix(keygen.EffectiveED25519PubKey(pubK), m.prefix)
}

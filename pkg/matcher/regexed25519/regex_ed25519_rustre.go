//go:build rustre

package regexed25519

import (
	rure "github.com/BurntSushi/rure-go"
	"github.com/Mattias-/vanity-ssh-keygen/pkg/keygen"
)

type regexEd25519Matcher struct {
	re *rure.Regex
}

func New() *regexEd25519Matcher {
	return &regexEd25519Matcher{}
}

func (m *regexEd25519Matcher) SetMatchString(matchString string) {
	m.re = rure.MustCompile(matchString)
}

func (m *regexEd25519Matcher) Match(s keygen.SSHKey) bool {
	pubK := s.SSHPubkey()
	return m.re.IsMatchBytes(keygen.EffectiveED25519PubKey(pubK))
}

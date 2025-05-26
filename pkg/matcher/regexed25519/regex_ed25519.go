//go:build !re2_cgo && !rustre

package regexed25519

import (
	"regexp"

	"github.com/Mattias-/vanity-ssh-keygen/pkg/keygen"
)

type regexEd25519Matcher struct {
	re *regexp.Regexp
}

func New() *regexEd25519Matcher {
	return &regexEd25519Matcher{}
}

func (m *regexEd25519Matcher) SetMatchString(matchString string) {
	m.re = regexp.MustCompile(matchString)
}

func (m *regexEd25519Matcher) Match(s keygen.SSHKey) bool {
	pubK := s.SSHPubkey()
	return m.re.Match(keygen.EffectiveED25519PubKey(pubK))
}

//go:build rure

package matcher

import (
	rure "github.com/BurntSushi/rure-go"
	"github.com/Mattias-/vanity-ssh-keygen/pkg/keygen"
)

type regexpMatcher struct {
	re        *rure.Regex
	getPubKey func([]byte) []byte
}

func (m *regexpMatcher) SetPattern(pattern string) {
	m.re = rure.MustCompile(pattern)
}

func (m *regexpMatcher) Match(s keygen.SSHKey) bool {
	return m.re.IsMatchBytes(m.getPubKey(s.SSHPubkey()))
}

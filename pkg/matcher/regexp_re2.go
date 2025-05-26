//go:build re2_cgo

package matcher

import (
	"regexp"

	"github.com/Mattias-/vanity-ssh-keygen/pkg/keygen"
)

type regexpMatcher struct {
	re        *regexp.Regexp
	getPubKey func([]byte) []byte
}

func (m *regexpMatcher) SetPattern(pattern string) {
	m.re = regexp.MustCompile(pattern)
}

func (m *regexpMatcher) Match(s keygen.SSHKey) bool {
	return m.re.Match(m.getPubKey(s.SSHPubkey()))
}

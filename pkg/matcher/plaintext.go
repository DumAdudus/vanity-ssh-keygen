package matcher

import (
	"bytes"
	"strings"

	"github.com/Mattias-/vanity-ssh-keygen/pkg/keygen"
)

type plainTextMatcher struct {
	pattern   string
	matchFunc plainTextMatchFunc
}

func New(matchFunc plainTextMatchFunc) *plainTextMatcher {
	return &plainTextMatcher{matchFunc: matchFunc}
}

func (m *plainTextMatcher) SetPattern(matchString string) {
	m.pattern = matchString
}

func (m *plainTextMatcher) Match(s keygen.SSHKey) bool {
	return m.matchFunc(s.SSHPubkey(), m.pattern)
}

type plainTextMatchFunc func(pubKey []byte, pattern string) bool

func IgnoreCase(pubKey []byte, pattern string) bool {
	return strings.Contains(strings.ToLower(string(pubKey)), pattern)
}

func IgnoreCaseED25519(pubKey []byte, pattern string) bool {
	return IgnoreCase(ED25519PubKey(pubKey), pattern)
}

func HasPrefix(pubKey []byte, pattern string) bool {
	return bytes.HasPrefix(pubKey, []byte(pattern))
}

func HasPrefixED25519(pubKey []byte, pattern string) bool {
	return bytes.HasPrefix(ED25519PubKey(pubKey), []byte(pattern))
}

func HasSuffix(pubKey []byte, pattern string) bool {
	return bytes.HasSuffix(pubKey, []byte(pattern))
}

func HasSuffixED25519(pubKey []byte, pattern string) bool {
	return bytes.HasSuffix(ED25519PubKey(pubKey), []byte(pattern))
}

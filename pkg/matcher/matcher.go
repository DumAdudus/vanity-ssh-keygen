package matcher

import (
	"github.com/Mattias-/vanity-ssh-keygen/pkg/keygen"
	"github.com/Mattias-/vanity-ssh-keygen/pkg/matcher/ignorecase"
	"github.com/Mattias-/vanity-ssh-keygen/pkg/matcher/ignorecaseed25519"
	"github.com/Mattias-/vanity-ssh-keygen/pkg/matcher/prefixed25519"
	"github.com/Mattias-/vanity-ssh-keygen/pkg/matcher/regexed25519"
	"github.com/Mattias-/vanity-ssh-keygen/pkg/matcher/suffixed25519"
)

var (
	_ Matcher = regexed25519.New()
	_ Matcher = prefixed25519.New()
	_ Matcher = suffixed25519.New()
	_ Matcher = ignorecase.New()
	_ Matcher = ignorecaseed25519.New()
)

type Matcher interface {
	SetMatchString(string)
	Match(keygen.SSHKey) bool
}

type namedMatcher struct {
	name    string
	matcher Matcher
}

var matchers = []namedMatcher{}

func RegisterMatcher(name string, m Matcher) {
	matchers = append(matchers, namedMatcher{name, m})
}

func Names() []string {
	names := make([]string, 0, len(matchers))
	for _, k := range matchers {
		names = append(names, k.name)
	}
	return names
}

func Get(name string) (Matcher, bool) {
	for _, m := range matchers {
		if m.name == name {
			return m.matcher, true
		}
	}
	return nil, false
}

func CommonPubKey(origin []byte) []byte {
	return origin
}

func ED25519PubKey(origin []byte) []byte {
	/*
	   The public key is 80 bytes long, the first 37 bytes are the key type and the key length, the last 43 bytes are the key itself
	   https://crypto.stackexchange.com/questions/44584/ed25519-ssh-public-key-is-always-80-characters-long
	   Example public key:
	   ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINyqBBX74InG199sb0Dg+5+vhuHbBimaTtiJb0+OGbzJ
	   |   Key type and length             || key                                     |

	   also, the key end with '\n', need to strip it
	*/

	return origin[37 : len(origin)-1]
}

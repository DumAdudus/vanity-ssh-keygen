package keygen

type SSHKey interface {
	SSHPubkey() []byte
	SSHPrivkey() []byte
	Generate()
}

type Keygen func() SSHKey

type namedKeygen struct {
	name   string
	keygen Keygen
}

var keygens = []namedKeygen{}

func RegisterKeygen(name string, k Keygen) {
	keygens = append(keygens, namedKeygen{name, k})
}

func Names() []string {
	names := make([]string, 0, len(keygens))
	for _, k := range keygens {
		names = append(names, k.name)
	}
	return names
}

func Get(name string) (Keygen, bool) {
	for _, k := range keygens {
		if k.name == name {
			return k.keygen, true
		}
	}
	return nil, false
}

func EffectiveED25519PubKey(origin []byte) []byte {
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

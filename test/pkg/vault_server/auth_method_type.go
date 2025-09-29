package vault_server

type AuthMethodType string

func (t AuthMethodType) String() string {
	return string(t)
}

func (t AuthMethodType) Path() string {
	return t.String()
}

const (
	AuthMethodJWT     = AuthMethodType("jwt")
	AuthMethodAppRole = AuthMethodType("approle")
)

package hashivault

import vault "github.com/hashicorp/vault/api"

type jwtAuthenticator struct {
	baseAuthenticator
	jwtToken string
	role     string
	path     string
}

func newJWTAuthenticator(path, jwtToken, role string) *jwtAuthenticator {
	return &jwtAuthenticator{
		baseAuthenticator: baseAuthenticator{},
		path:              path,
		jwtToken:          jwtToken,
		role:              role,
	}
}

func (j *jwtAuthenticator) Login(client *vault.Client) error {
	loginData := map[string]interface{}{
		"role": j.role,
		"jwt":  j.jwtToken,
	}
	return j.baseAuthenticator.login(client, j.path, loginData)
}

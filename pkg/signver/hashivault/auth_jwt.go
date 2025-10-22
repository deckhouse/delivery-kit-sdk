package hashivault

import vault "github.com/hashicorp/vault/api"

type jwtAuthenticator struct {
	baseAuthenticator
	jwtToken string
	role     string
}

func newJWTAuthenticator(jwtToken, role string) *jwtAuthenticator {
	return &jwtAuthenticator{
		baseAuthenticator: baseAuthenticator{
			authPath: "jwt",
		},
		jwtToken: jwtToken,
		role:     role,
	}
}

func (j *jwtAuthenticator) Login(client *vault.Client) error {
	loginData := map[string]interface{}{
		"role": j.role,
		"jwt":  j.jwtToken,
	}
	return j.baseAuthenticator.login(client, loginData)
}

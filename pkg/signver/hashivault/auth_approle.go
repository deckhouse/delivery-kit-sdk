package hashivault

import vault "github.com/hashicorp/vault/api"

type appRoleAuthenticator struct {
	baseAuthenticator
	roleID   string
	secretID string
}

func newAppRoleAuthenticator(roleID, secretID string) *appRoleAuthenticator {
	return &appRoleAuthenticator{
		baseAuthenticator: baseAuthenticator{
			loginNamespace: "ar",
		},
		roleID:   roleID,
		secretID: secretID,
	}
}

func (a *appRoleAuthenticator) Login(client *vault.Client) error {
	loginData := map[string]interface{}{
		"role_id":   a.roleID,
		"secret_id": a.secretID,
	}
	return a.baseAuthenticator.login(client, loginData)
}

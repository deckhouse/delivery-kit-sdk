package hashivault

import (
	"k8s.io/utils/env"
)

func getVaultAuthRoleId() string {
	return env.GetString("WERF_VAULT_AUTH_ROLE_ID", env.GetString("VAULT_ROLE_ID", ""))
}

func getVaultAuthSecretId() string {
	return env.GetString("WERF_VAULT_AUTH_SECRET_ID", env.GetString("VAULT_SECRET_ID", ""))
}

func getVaultAuthRole() string {
	return env.GetString("WERF_VAULT_AUTH_ROLE", "")
}

func getVaultAuthJwt() string {
	return env.GetString("WERF_VAULT_AUTH_JWT", "")
}

func getVaultAuthPath() string {
	return env.GetString("WERF_VAULT_AUTH_PATH", "")
}

func getActionsAudience() string {
	return env.GetString("WERF_ACTIONS_AUDIENCE", "")
}

func getActionsIDTokenRequestURL() string {
	return env.GetString("ACTIONS_ID_TOKEN_REQUEST_URL", "")
}

func getActionsIDTokenRequestToken() string {
	return env.GetString("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
}

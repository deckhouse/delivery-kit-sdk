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

func getVaultAuthNamespace() string {
	return env.GetString("WERF_VAULT_AUTH_NAMESPACE", "")
}

package hashivault

import (
	"fmt"
)

type authenticatorSettings struct {
	token, roleID, secretID, authPath, audience, authRole, jwtToken string
	fromEnv                                                         bool
}

func newAuthSettings(opts VaultOpts) authenticatorSettings {
	if !opts.hasAuthOpts() {
		return authenticatorSettings{
			roleID:   getVaultAuthRoleId(),
			secretID: getVaultAuthSecretId(),
			authPath: getVaultAuthPath(),
			audience: getActionsAudience(),
			authRole: getVaultAuthRole(),
			jwtToken: getVaultAuthJwt(),
			fromEnv:  true,
		}
	}

	return authenticatorSettings{
		token:    opts.Token,
		roleID:   opts.AuthRoleID,
		secretID: opts.AuthSecretID,
		authPath: opts.AuthPath,
		authRole: opts.AuthRole,
		jwtToken: opts.AuthJWT,
		audience: opts.Audience,
		fromEnv:  false,
	}
}

func newAuthenticator(settings authenticatorSettings) (authenticator, error) {
	if settings.roleID != "" && settings.secretID != "" {
		return newAppRoleAuthenticator(settings.roleID, settings.secretID, settings.authPath), nil
	} else if settings.audience != "" {
		requestURL := getActionsIDTokenRequestURL()
		requestToken := getActionsIDTokenRequestToken()
		if requestURL == "" {
			return nil, fmt.Errorf("WERF_ACTIONS_AUDIENCE is set but ACTIONS_ID_TOKEN_REQUEST_URL is missing")
		}
		if requestToken == "" {
			return nil, fmt.Errorf("WERF_ACTIONS_AUDIENCE is set but ACTIONS_ID_TOKEN_REQUEST_TOKEN is missing")
		}
		provider := newActionsOidcJwtTokenProvider(requestURL, requestToken, settings.audience)
		return newJWTAuthenticator(provider, settings.authRole, settings.authPath), nil
	} else if settings.jwtToken != "" {
		provider := newStaticJwtTokenProvider(settings.jwtToken)
		return newJWTAuthenticator(provider, settings.authRole, settings.authPath), nil
	}

	if !settings.fromEnv {
		if settings.token == "" {
			return nil, fmt.Errorf("incomplete Vault auth options: provide a complete AppRole (role id + secret id), a JWT, an OIDC audience, or a token")
		}
		return newStaticAuthProvider(settings.token), nil
	}

	token, err := getVaultToken(settings.token)
	if err != nil {
		return nil, err
	}
	return newStaticAuthProvider(token), nil
}

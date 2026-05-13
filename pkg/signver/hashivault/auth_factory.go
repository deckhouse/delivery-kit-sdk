package hashivault

import "fmt"

func newAuthenticator(token string) (authenticator, error) {
	if roleID, secretID := getVaultAuthRoleId(), getVaultAuthSecretId(); roleID != "" && secretID != "" {
		return newAppRoleAuthenticator(roleID, secretID), nil
	} else if audience := getActionsAudience(); audience != "" {
		requestURL := getActionsIDTokenRequestURL()
		requestToken := getActionsIDTokenRequestToken()
		if requestURL == "" {
			return nil, fmt.Errorf("WERF_ACTIONS_AUDIENCE is set but ACTIONS_ID_TOKEN_REQUEST_URL is missing")
		}
		if requestToken == "" {
			return nil, fmt.Errorf("WERF_ACTIONS_AUDIENCE is set but ACTIONS_ID_TOKEN_REQUEST_TOKEN is missing")
		}
		provider := newActionsOidcJwtTokenProvider(requestURL, requestToken, audience)
		return newJWTAuthenticator(provider, getVaultAuthRole()), nil
	} else if jwtToken := getVaultAuthJwt(); jwtToken != "" {
		provider := newStaticJwtTokenProvider(jwtToken)
		return newJWTAuthenticator(provider, getVaultAuthRole()), nil
	}

	token, err := getVaultToken(token)
	if err != nil {
		return nil, err
	}
	return newStaticAuthProvider(token), nil
}

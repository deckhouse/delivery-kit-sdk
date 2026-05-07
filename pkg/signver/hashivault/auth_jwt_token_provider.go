package hashivault

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// jwtTokenProvider defines the interface for obtaining a JWT token
// used for Vault authentication via the JWT auth method.
type jwtTokenProvider interface {
	GetToken() (string, error)
}

// --- staticJwtTokenProvider ---

// staticJwtTokenProvider holds a static JWT token, obtained once at initialization time.
// Suitable for CI systems where the JWT has a long TTL (e.g., GitLab CI with 6h token lifetime).
type staticJwtTokenProvider struct {
	token string
}

func newStaticJwtTokenProvider(token string) *staticJwtTokenProvider {
	return &staticJwtTokenProvider{token: token}
}

func (p *staticJwtTokenProvider) GetToken() (string, error) {
	if p.token == "" {
		return "", fmt.Errorf("static JWT token is empty")
	}
	return p.token, nil
}

// --- actionsOidcJwtTokenProvider ---

// actionsOidcJwtTokenProvider requests a fresh OIDC token from the GitHub Actions
// OIDC endpoint (ACTIONS_ID_TOKEN_REQUEST_URL) before each Vault login.
// This solves the 10-minute token expiry issue in GitHub Actions.
type actionsOidcJwtTokenProvider struct {
	requestURL   string
	requestToken string
	audience     string
}

func newActionsOidcJwtTokenProvider(requestURL, requestToken, audience string) *actionsOidcJwtTokenProvider {
	return &actionsOidcJwtTokenProvider{
		requestURL:   requestURL,
		requestToken: requestToken,
		audience:     audience,
	}
}

type idTokenResponse struct {
	Value string `json:"value"`
}

func (p *actionsOidcJwtTokenProvider) GetToken() (string, error) {
	req, err := http.NewRequest(http.MethodGet, p.requestURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create OIDC token request: %w", err)
	}

	q := req.URL.Query()
	q.Set("audience", p.audience)
	req.URL.RawQuery = q.Encode()

	req.Header.Set("Authorization", "Bearer "+p.requestToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to request OIDC token from GitHub Actions: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read OIDC token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OIDC endpoint returned status %d: %s", resp.StatusCode, body)
	}

	var tokenResp idTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("failed to parse OIDC token response: %w", err)
	}

	if tokenResp.Value == "" {
		return "", fmt.Errorf("OIDC endpoint returned an empty token")
	}

	return tokenResp.Value, nil
}

package hashivault

import (
	"fmt"
	"time"

	vault "github.com/hashicorp/vault/api"
)

type baseAuthenticator struct {
	authPath      string
	tokenID       string
	tokenTTL      time.Duration
	tokenIssuedAt time.Time
}

func (b *baseAuthenticator) login(client *vault.Client, data map[string]interface{}) error {
	b.tokenIssuedAt = time.Now()

	resp, err := client.Logical().Write(fmt.Sprintf("/auth/%s/login", b.getAuthPath()), data)
	if err != nil {
		return fmt.Errorf("vault write: %w", err)
	}

	tokenID, err := resp.TokenID()
	if err != nil {
		return fmt.Errorf("getting auth token id: %w", err)
	}
	tokenTTL, err := resp.TokenTTL()
	if err != nil {
		return fmt.Errorf("getting auth token TTL: %w", err)
	}

	b.tokenID = tokenID
	b.tokenTTL = tokenTTL

	client.SetToken(b.tokenID)

	return nil
}

// isTokenValid checks if the cached Vault token is still valid.
// A safety margin of 30 seconds is used to avoid edge cases with token expiration.
func (b *baseAuthenticator) isTokenValid() bool {
	if b.tokenID == "" {
		return false
	}
	if b.tokenTTL <= 0 {
		return false
	}
	elapsed := time.Since(b.tokenIssuedAt)
	// Re-authenticate if less than 30 seconds remain before expiration
	return elapsed < b.tokenTTL-30*time.Second
}

func (b *baseAuthenticator) getAuthPath() string {
	if authPath := getVaultAuthPath(); authPath != "" {
		return authPath
	}
	return b.authPath
}

func (b *baseAuthenticator) Login(client *vault.Client) error {
	panic("not implemented")
}

func (b *baseAuthenticator) TokenTTL() time.Duration {
	return b.tokenTTL
}

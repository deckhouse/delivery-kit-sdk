package hashivault

import (
	"fmt"
	"time"

	vault "github.com/hashicorp/vault/api"
)

type baseAuthenticator struct {
	loginNamespace string
	tokenID        string
	tokenTTL       time.Duration
	tokenIssuedAt  time.Time
}

func (b *baseAuthenticator) login(client *vault.Client, data map[string]interface{}) error {
	b.tokenIssuedAt = time.Now()

	resp, err := client.Logical().Write(fmt.Sprintf("/auth/%s/login", b.getLoginNamespace()), data)
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

func (b *baseAuthenticator) getLoginNamespace() string {
	if namespace := getVaultAuthPath(); namespace != "" {
		return namespace
	}
	return b.loginNamespace
}

func (b *baseAuthenticator) Login(client *vault.Client) error {
	panic("not implemented")
}

func (b *baseAuthenticator) TokenTTL() time.Duration {
	return b.tokenTTL
}

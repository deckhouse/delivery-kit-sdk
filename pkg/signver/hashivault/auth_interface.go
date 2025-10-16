package hashivault

import (
	"time"

	vault "github.com/hashicorp/vault/api"
)

type authenticator interface {
	Login(client *vault.Client) error
	TokenTTL() time.Duration
}

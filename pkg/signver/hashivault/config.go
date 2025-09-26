package hashivault

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/mitchellh/go-homedir"
)

func getVaultAddress(address string) (string, error) {
	if address != "" {
		return address, nil
	}
	if address = os.Getenv("VAULT_ADDR"); address == "" {
		return "", errors.New("VAULT_ADDR is not set")
	} else {
		return address, nil
	}
}

func getVaultToken(token string) (string, error) {
	if token != "" {
		return token, nil
	}

	if token = os.Getenv("VAULT_TOKEN"); token == "" {
		log.Printf("VAULT_TOKEN is not set, trying to read token from file at path ~/.vault-token")
		homeDir, err := homedir.Dir()
		if err != nil {
			return "", fmt.Errorf("get home directory: %w", err)
		}

		tokenFromFile, err := os.ReadFile(filepath.Join(homeDir, ".vault-token"))
		if err != nil {
			return "", fmt.Errorf("read .vault-token file: %w", err)
		}

		token = string(tokenFromFile)
	}

	if token == "" {
		return "", errors.New("VAULT_TOKEN is not set")
	}

	return token, nil
}

func getVaultTransitSecretEnginePath(transitSecretEnginePath string) string {
	if transitSecretEnginePath != "" {
		return transitSecretEnginePath
	}

	if transitSecretEnginePath = os.Getenv("TRANSIT_SECRET_ENGINE_PATH"); transitSecretEnginePath != "" {
		return transitSecretEnginePath
	}

	return "transit"
}

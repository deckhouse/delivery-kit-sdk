package hashivault

import (
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
)

const (
	vaultV1DataPrefix = "vault:v1:"
)

// Vault likes to prefix base64 data with a version prefix
func vaultDecode(data interface{}, keyVersionUsed *string) ([]byte, error) {
	encoded, ok := data.(string)
	if !ok {
		return nil, errors.New("received non-string data")
	}

	if keyVersionUsed != nil {
		*keyVersionUsed = prefixRegex.FindString(encoded)
	}
	return base64.StdEncoding.DecodeString(prefixRegex.ReplaceAllString(encoded, ""))
}

func determineVaultDataPrefix(keyVersion string, defaultKeyVersion uint64) (string, error) {
	var vaultDataPrefix string
	if keyVersion != "" {
		// keyVersion >= 1 on verification but can be set to 0 on signing
		kvUint, err := strconv.ParseUint(keyVersion, 10, 64)
		if err != nil {
			return "", fmt.Errorf("parsing requested key version: %w", err)
		} else if kvUint == 0 {
			return "", errors.New("key version must be >= 1")
		}

		vaultDataPrefix = fmt.Sprintf("vault:v%d:", kvUint)
	} else {
		vaultDataPrefix = os.Getenv("VAULT_KEY_PREFIX")
		if vaultDataPrefix == "" {
			if defaultKeyVersion > 0 {
				vaultDataPrefix = fmt.Sprintf("vault:v%d:", defaultKeyVersion)
			} else {
				vaultDataPrefix = vaultV1DataPrefix
			}
		}
	}

	return vaultDataPrefix, nil
}

func hashString(h crypto.Hash) string {
	var hashStr string
	switch h {
	case crypto.SHA224:
		hashStr = "/sha2-224"
	case crypto.SHA256:
		hashStr = "/sha2-256"
	case crypto.SHA384:
		hashStr = "/sha2-384"
	case crypto.SHA512:
		hashStr = "/sha2-512"
	default:
		hashStr = ""
	}
	return hashStr
}

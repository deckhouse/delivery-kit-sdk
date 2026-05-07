package image_test

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"

	"github.com/deckhouse/delivery-kit-sdk/test/pkg/cert_utils"
	"github.com/deckhouse/delivery-kit-sdk/test/pkg/vault_server"
)

func vaultKeyType(keyType cert_utils.KeyType) vault_server.TransitKeyType {
	switch keyType {
	case cert_utils.KeyType_ECDSA_P256:
		return vault_server.TransitKeyType_ECDSA256
	case cert_utils.KeyType_ED25519:
		return vault_server.TransitKeyType_ED25519
	default:
		panic(fmt.Sprintf("unsupported key type: %d", keyType))
	}
}

func jwtAlgorithm(keyType cert_utils.KeyType) string {
	switch keyType {
	case cert_utils.KeyType_ECDSA_P256:
		return "ES256"
	case cert_utils.KeyType_ED25519:
		return "EdDSA"
	default:
		panic(fmt.Sprintf("unsupported key type for JWT algorithm: %d", keyType))
	}
}

func jwtSigningMethod(keyType cert_utils.KeyType) jwt.SigningMethod {
	switch keyType {
	case cert_utils.KeyType_ECDSA_P256:
		return jwt.SigningMethodES256
	case cert_utils.KeyType_ED25519:
		return jwt.SigningMethodEdDSA
	default:
		panic(fmt.Sprintf("unsupported key type for JWT signing method: %d", keyType))
	}
}

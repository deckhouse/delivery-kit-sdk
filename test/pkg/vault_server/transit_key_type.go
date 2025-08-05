package vault_server

type TransitKeyType string

func (t TransitKeyType) String() string {
	return string(t)
}

const (
	// TransitKeyType_ECDSA256 https://developer.hashicorp.com/vault/api-docs/secret/transit#import-key
	TransitKeyType_ECDSA256 = TransitKeyType("ecdsa-p256")
	TransitKeyType_ED25519  = TransitKeyType("ed25519")
)

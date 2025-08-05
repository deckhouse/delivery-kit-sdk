package vault_server

type TransitKeyType string

func (t TransitKeyType) String() string {
	return string(t)
}

const (
	// TransitKeyTypeECDSA256 https://developer.hashicorp.com/vault/api-docs/secret/transit#import-key
	TransitKeyTypeECDSA256 = TransitKeyType("ecdsa-p256")
)

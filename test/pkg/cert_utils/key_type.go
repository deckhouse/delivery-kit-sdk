package cert_utils

type KeyType int

const (
	KeyType_ECDSA_P256 KeyType = iota
	KeyType_ED25519
)

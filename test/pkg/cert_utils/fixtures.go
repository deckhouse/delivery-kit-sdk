package cert_utils

import (
	_ "embed"
	"encoding/base64"
)

//go:embed signer.key
var signerKey []byte

//go:embed signer.crt
var signerCert []byte

//go:embed signer-chain.pem
var signerChain []byte

//go:embed rootCA.crt
var rootCA []byte

//go:embed unknownRootCA.crt
var unknownRootCA []byte

var (
	SignerKeyBase64     = base64.StdEncoding.EncodeToString(signerKey)
	SignerCertBase64    = base64.StdEncoding.EncodeToString(signerCert)
	SignerChainBase64   = base64.StdEncoding.EncodeToString(signerChain)
	RootCABase64        = base64.StdEncoding.EncodeToString(rootCA)
	UnknownRootCABase64 = base64.StdEncoding.EncodeToString(unknownRootCA)
)

package signature

import (
	"encoding/base64"
)

type Bundle struct {
	Signature BundleItem
	Cert      BundleItem
	Chain     BundleItem
}

type BundleItem []byte

func (item BundleItem) Base64String() string {
	return base64.StdEncoding.EncodeToString(item)
}

func NewBundle(sig, cert, chain BundleItem) *Bundle {
	return &Bundle{
		Signature: sig,
		Cert:      cert,
		Chain:     chain,
	}
}

package image_test

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sigstore/sigstore/pkg/cryptoutils"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signver"
	"github.com/deckhouse/delivery-kit-sdk/test/pkg/cert_utils"
	"github.com/deckhouse/delivery-kit-sdk/test/pkg/vault_server"
)

var _ = Describe("manifest", Serial, func() {
	DescribeTable("sign and verify image manifest using Vault Transit",
		func(ctx SpecContext, keyType cert_utils.KeyType) {
			tmpDir := GinkgoT().TempDir()

			vaultServer := vault_server.NewVaultServer(tmpDir)
			vaultServer.Stop(ctx) // Ensure the server is stopped
			vaultServer.Start(ctx)
			defer vaultServer.Stop(ctx)
			vaultServer.Ready(ctx)

			vaultNamespace := "my-namespace"
			vaultServer.EnableTransit(ctx, vaultNamespace)

			// Import key. IMPORTANT: the key must be in {PKCS #8 ASN.1 DER} form.
			// https://developer.hashicorp.com/vault/docs/secrets/transit#manual-process
			// Vault Transit CLI Examples:
			// https://developer.hashicorp.com/vault/docs/commands/transit#examples
			// Bring your own key (BYOK)
			// https://developer.hashicorp.com/vault/docs/secrets/transit#bring-your-own-key-byok

			certGen := cert_utils.GenerateCertificatesWithOptions(cert_utils.GenerateCertificatesOptions{
				KeyType:                      keyType,
				PassFunc:                     cryptoutils.SkipPassword,
				TmpDir:                       tmpDir,
				NoIntermediates:              true,
				ExcludeRootFromIntermediates: true,
			})

			x509PKCS8Encoded, err := x509.MarshalPKCS8PrivateKey(certGen.PrivKey)
			Expect(err).To(Succeed())

			x509PKCS8Base64Encoded := make([]byte, base64.StdEncoding.EncodedLen(len(x509PKCS8Encoded)))
			base64.StdEncoding.Encode(x509PKCS8Base64Encoded, x509PKCS8Encoded)

			prvKeyAsn1DerFileName := cert_utils.MakeFile(tmpDir, "sigstore_*.asn1.der.base64.key", x509PKCS8Base64Encoded)

			vaultEndpoint := "endpoint"

			vaultServer.ImportTransitKey(ctx, vaultNamespace, vaultEndpoint, prvKeyAsn1DerFileName, vaultKeyType(keyType))

			_, chainRef, err := signver.ConcatChain(certGen.IntermediatesRef, certGen.RootRef)
			Expect(err).To(Succeed())

			Expect(os.Setenv("TRANSIT_SECRET_ENGINE_PATH", vaultNamespace))
			Expect(os.Setenv("VAULT_ADDR", vaultServer.Addr))
			Expect(os.Setenv("VAULT_TOKEN", vaultServer.RootToken))

			sv, err := signver.NewSignerVerifier(ctx, certGen.LeafRef, chainRef, signver.KeyOpts{
				KeyRef:   fmt.Sprintf("hashivault://%s", vaultEndpoint),
				PassFunc: cryptoutils.SkipPassword,
			})
			Expect(err).To(Succeed())

			test(ctx, sv, certGen.RootRef)
		},
		Entry(
			"ECDSA_P256 key, without intermediates, root cert not in chain, certs are file paths",
			cert_utils.KeyType_ECDSA_P256,
		),
		// TODO: we don't support ED25519 key type right now
		XEntry(
			"ED25519 key, without intermediates, root cert not in chain, certs are file paths",
			cert_utils.KeyType_ED25519,
		),
	)
})

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

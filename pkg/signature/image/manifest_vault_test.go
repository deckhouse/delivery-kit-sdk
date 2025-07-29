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
	DescribeTable("sign and verify image manifest using local Vault",
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
			Expect(os.Setenv("VAULT_ADDR", vaultServer.Addr.String()))
			Expect(os.Setenv("VAULT_TOKEN", vaultServer.RootToken))

			sv, err := signver.NewSignerVerifier(ctx, certGen.LeafRef, chainRef, signver.KeyOpts{
				KeyRef:   fmt.Sprintf("hashivault://%s", vaultEndpoint),
				PassFunc: cryptoutils.SkipPassword,
			})
			Expect(err).To(Succeed())

			imgOriginal, sigAnnotations := testSign(ctx, sv)
			testVerify(ctx, imgOriginal, sigAnnotations, certGen.RootRef)
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

	DescribeTable("sign and verify image manifest using remote Vault",
		func(ctx SpecContext, keyRef, certRef, chainRef, rootRef string, useVerification bool) {
			skipTestIfEnvironmentVariablesNotSet()

			sv, err := signver.NewSignerVerifier(ctx, certRef, chainRef, signver.KeyOpts{
				KeyRef: keyRef,
			})
			Expect(err).To(Succeed())

			imgOriginal, sigAnnotations := testSign(ctx, sv)

			if !useVerification {
				return
			}

			testVerify(ctx, imgOriginal, sigAnnotations, rootRef)
		},
		Entry(
			"should sign image manifest using ED25519 key",
			"hashivault://dh-2025-july",
			"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUMyVENDQW91Z0F3SUJBZ0lVVUdLZDkyUkJGQ3dYL3Jla3ZsTE5taTRJd3pJd0JRWURLMlZ3TUhzeEN6QUoKQmdOVkJBWVRBbEpWTVE4d0RRWURWUVFJRXdaTmIzTmpiM2N4RHpBTkJnTlZCQWNUQmsxdmMyTnZkekVTTUJBRwpBMVVFQ2hNSlNsTkRJRVpzWVc1ME1SSXdFQVlEVlFRTEV3bEVaV05yYUc5MWMyVXhJakFnQmdOVkJBTVRHVXBUClF5QkdiR0Z1ZENCSmJuUmxjbTFsWkdsaGRHVWdRMEV3SGhjTk1qVXdOekl4TVRNek5UQXhXaGNOTWpZd09ESXcKTVRNek5UTXhXakI0TVFzd0NRWURWUVFHRXdKU1ZURVBNQTBHQTFVRUNCTUdUVzl6WTI5M01ROHdEUVlEVlFRSApFd1pOYjNOamIzY3hFakFRQmdOVkJBb1RDVXBUUXlCR2JHRnVkREVTTUJBR0ExVUVDeE1KUkdWamEyaHZkWE5sCk1SOHdIUVlEVlFRRERCWmthQzF6YVdkdVpYSkFaR1ZqYTJodmRYTmxMbkoxTUNvd0JRWURLMlZ3QXlFQXpMWmQKajRtTnNvUkFFeFlmV3dWdExtdHpWWjRxekRIUmhVbVJDVEJrMDJDamdnRWlNSUlCSGpBT0JnTlZIUThCQWY4RQpCQU1DQTZnd0hRWURWUjBsQkJZd0ZBWUlLd1lCQlFVSEF3RUdDQ3NHQVFVRkJ3TUNNQjBHQTFVZERnUVdCQlQ2CkxubGtjMkRobythZFg0YjFjYk11VXBQSnBUQWZCZ05WSFNNRUdEQVdnQlFXSWdlNW83NjFqakE5VEZzaGhsVWUKR3duUDZ6QkpCZ2dyQmdFRkJRY0JBUVE5TURzd09RWUlLd1lCQlFVSE1BS0dMV2gwZEhCek9pOHZNVEkzTGpBdQpNQzR4T2pneU1EQXZkakV2Y0d0cExXWnNZVzUwTFdsdWRDMWthQzlqWVRBaEJnTlZIUkVFR2pBWWdSWmthQzF6CmFXZHVaWEpBWkdWamEyaHZkWE5sTG5KMU1EOEdBMVVkSHdRNE1EWXdOS0F5b0RDR0xtaDBkSEJ6T2k4dk1USTMKTGpBdU1DNHhPamd5TURBdmRqRXZjR3RwTFdac1lXNTBMV2x1ZEMxa2FDOWpjbXd3QlFZREsyVndBMEVBSGNseApCamF0aVVDOEN3SnNWalE4RUVrdHIwYVlQNnBNc0dDL3QrWkhMWUJSOVk3UmhxclFvb3lNVE5URXFnbE43REp5ClRuQ2I0U21yTEY0YnpmZDdDQT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0=",
			"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNvakNDQWxTZ0F3SUJBZ0lVWmNiNE9WTmhhbXJOTU53dlRFT1J5RGFJMHhjd0JRWURLMlZ3TUhneEN6QUoKQmdOVkJBWVRBbEpWTVE4d0RRWURWUVFJRXdaTmIzTmpiM2N4RHpBTkJnTlZCQWNUQmsxdmMyTnZkekVTTUJBRwpBMVVFQ2hNSlNsTkRJRVpzWVc1ME1SQXdEZ1lEVlFRTEV3ZEpibVp2YzJWak1TRXdId1lEVlFRREV4aEtVME1nClJteGhiblFnVW05dmRDQkRRU0JCTFRJd01qVXdIaGNOTWpVd056SXhNVE16TXpVeldoY05NelV3TnpFNU1UTXoKTkRJeldqQjdNUXN3Q1FZRFZRUUdFd0pTVlRFUE1BMEdBMVVFQ0JNR1RXOXpZMjkzTVE4d0RRWURWUVFIRXdaTgpiM05qYjNjeEVqQVFCZ05WQkFvVENVcFRReUJHYkdGdWRERVNNQkFHQTFVRUN4TUpSR1ZqYTJodmRYTmxNU0l3CklBWURWUVFERXhsS1UwTWdSbXhoYm5RZ1NXNTBaWEp0WldScFlYUmxJRU5CTUNvd0JRWURLMlZ3QXlFQTYyeG4KcVJEUm5uSGZDRXJlNFliYW55aDNDT2p6Z3N1alFSenJGSlVtS2Ztamdld3dnZWt3RGdZRFZSMFBBUUgvQkFRRApBZ0VHTUE4R0ExVWRFd0VCL3dRRk1BTUJBZjh3SFFZRFZSME9CQllFRkJZaUI3bWp2cldPTUQxTVd5R0dWUjRiCkNjL3JNQjhHQTFVZEl3UVlNQmFBRkpCZ0s0NjYzVVdZMEhKbTVGb1plK1Rsem1mek1FY0dDQ3NHQVFVRkJ3RUIKQkRzd09UQTNCZ2dyQmdFRkJRY3dBb1lyYUhSMGNITTZMeTh4TWpjdU1DNHdMakU2T0RJd01DOTJNUzl3YTJrdApabXhoYm5RdGNtOXZkQzlqWVRBOUJnTlZIUjhFTmpBME1ES2dNS0F1aGl4b2RIUndjem92THpFeU55NHdMakF1Ck1UbzRNakF3TDNZeEwzQnJhUzFtYkdGdWRDMXliMjkwTDJOeWJEQUZCZ01yWlhBRFFRQnNOZWNUU0l6bmxvQWYKYkViU2JERlpGb20wMXc2WDN5WVpqVmFOQngrNEZmV3JNZ1ppU05rM3NkZ0dNRlpEVnVaZWl4OXlQUTk3bVIzWgpaTXU0Q3JRUAotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0t",
			"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNGVENDQWNlZ0F3SUJBZ0lVZElhblV0Nk0vNnFTL0RzMXJWSjZoc09JTmYwd0JRWURLMlZ3TUhneEN6QUoKQmdOVkJBWVRBbEpWTVE4d0RRWURWUVFJRXdaTmIzTmpiM2N4RHpBTkJnTlZCQWNUQmsxdmMyTnZkekVTTUJBRwpBMVVFQ2hNSlNsTkRJRVpzWVc1ME1SQXdEZ1lEVlFRTEV3ZEpibVp2YzJWak1TRXdId1lEVlFRREV4aEtVME1nClJteGhiblFnVW05dmRDQkRRU0JCTFRJd01qVXdIaGNOTWpVd056SXhNVE15TkRVMFdoY05ORFV3TnpFMk1UTXkKTlRJMFdqQjRNUXN3Q1FZRFZRUUdFd0pTVlRFUE1BMEdBMVVFQ0JNR1RXOXpZMjkzTVE4d0RRWURWUVFIRXdaTgpiM05qYjNjeEVqQVFCZ05WQkFvVENVcFRReUJHYkdGdWRERVFNQTRHQTFVRUN4TUhTVzVtYjNObFl6RWhNQjhHCkExVUVBeE1ZU2xORElFWnNZVzUwSUZKdmIzUWdRMEVnUVMweU1ESTFNQ293QlFZREsyVndBeUVBbGd1Q3hQRHUKV1VhajZjazZHdFIrZGdCNS9SRENSNmdhSWkzN3ZCQmx0ZE9qWXpCaE1BNEdBMVVkRHdFQi93UUVBd0lCQmpBUApCZ05WSFJNQkFmOEVCVEFEQVFIL01CMEdBMVVkRGdRV0JCU1FZQ3VPdXQxRm1OQnladVJhR1h2azVjNW44ekFmCkJnTlZIU01FR0RBV2dCU1FZQ3VPdXQxRm1OQnladVJhR1h2azVjNW44ekFGQmdNclpYQURRUUJxbTd5S21mVG0KV01PcFdHRldxSVJLcmJnRW44NkpyQmVWSXFXakVUMWs2NEVjR2pFN0JkdWxqdjdDVGhCQ2xwY1c3bzFuUGlVeApZeDFUNnMvSmU3b0kKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=",
			false,
		),
		Entry(
			"should sign and verify image manifest using ECDSA_P256 key",
			"hashivault://dh-2025-aug-ec",
			"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUN0ekNDQW1tZ0F3SUJBZ0lVS25kUFo2aFl4Sm9pWW9kMkxmbVB4elFmcUNnd0JRWURLMlZ3TUhzeEN6QUoKQmdOVkJBWVRBbEpWTVE4d0RRWURWUVFJRXdaTmIzTmpiM2N4RHpBTkJnTlZCQWNUQmsxdmMyTnZkekVTTUJBRwpBMVVFQ2hNSlNsTkRJRVpzWVc1ME1SSXdFQVlEVlFRTEV3bEVaV05yYUc5MWMyVXhJakFnQmdOVkJBTVRHVXBUClF5QkdiR0Z1ZENCSmJuUmxjbTFsWkdsaGRHVWdRMEV3SGhjTk1qVXdPREEzTURnMU1qRTVXaGNOTWpZd09UQTIKTURnMU1qUTVXakFrTVNJd0lBWURWUVFEREJsa2FDMXphV2R1WlhJdFpXTkFaR1ZqYTJodmRYTmxMbkoxTUZrdwpFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRWlXRFNwWWRkcVBHY2h4SUIxZ1lTMmhwNVVKMkxMT1pHClpTYnNTSGdkVnRxZ2F2NE9WVGlKcHJVcFVXbjA4UG9LQndZOEdOU2dPaEhIZlU5NTYzV09TcU9DQVNVd2dnRWgKTUE0R0ExVWREd0VCL3dRRUF3SURxREFkQmdOVkhTVUVGakFVQmdnckJnRUZCUWNEQVFZSUt3WUJCUVVIQXdJdwpIUVlEVlIwT0JCWUVGSWRUK3RuS0ZmTjJ3YU1DYjV0ZGdITlJreEVNTUI4R0ExVWRJd1FZTUJhQUZCWWlCN21qCnZyV09NRDFNV3lHR1ZSNGJDYy9yTUVrR0NDc0dBUVVGQndFQkJEMHdPekE1QmdnckJnRUZCUWN3QW9ZdGFIUjAKY0hNNkx5OHhNamN1TUM0d0xqRTZPREl3TUM5Mk1TOXdhMmt0Wm14aGJuUXRhVzUwTFdSb0wyTmhNQ1FHQTFVZApFUVFkTUJ1QkdXUm9MWE5wWjI1bGNpMWxZMEJrWldOcmFHOTFjMlV1Y25Vd1B3WURWUjBmQkRnd05qQTBvREtnCk1JWXVhSFIwY0hNNkx5OHhNamN1TUM0d0xqRTZPREl3TUM5Mk1TOXdhMmt0Wm14aGJuUXRhVzUwTFdSb0wyTnkKYkRBRkJnTXJaWEFEUVFBRy8zQXlWMFJSS3lRSnFHT0ZOTU5GRTNiNzUrL3ViRGJwamVFaHhEcHNQMHB3ZU5abApmVUxqRmgwSVBob2k0TlB5L0pYYVVidWNycG45K2RWcDRHQUQKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=",
			"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNvakNDQWxTZ0F3SUJBZ0lVWmNiNE9WTmhhbXJOTU53dlRFT1J5RGFJMHhjd0JRWURLMlZ3TUhneEN6QUoKQmdOVkJBWVRBbEpWTVE4d0RRWURWUVFJRXdaTmIzTmpiM2N4RHpBTkJnTlZCQWNUQmsxdmMyTnZkekVTTUJBRwpBMVVFQ2hNSlNsTkRJRVpzWVc1ME1SQXdEZ1lEVlFRTEV3ZEpibVp2YzJWak1TRXdId1lEVlFRREV4aEtVME1nClJteGhiblFnVW05dmRDQkRRU0JCTFRJd01qVXdIaGNOTWpVd056SXhNVE16TXpVeldoY05NelV3TnpFNU1UTXoKTkRJeldqQjdNUXN3Q1FZRFZRUUdFd0pTVlRFUE1BMEdBMVVFQ0JNR1RXOXpZMjkzTVE4d0RRWURWUVFIRXdaTgpiM05qYjNjeEVqQVFCZ05WQkFvVENVcFRReUJHYkdGdWRERVNNQkFHQTFVRUN4TUpSR1ZqYTJodmRYTmxNU0l3CklBWURWUVFERXhsS1UwTWdSbXhoYm5RZ1NXNTBaWEp0WldScFlYUmxJRU5CTUNvd0JRWURLMlZ3QXlFQTYyeG4KcVJEUm5uSGZDRXJlNFliYW55aDNDT2p6Z3N1alFSenJGSlVtS2Ztamdld3dnZWt3RGdZRFZSMFBBUUgvQkFRRApBZ0VHTUE4R0ExVWRFd0VCL3dRRk1BTUJBZjh3SFFZRFZSME9CQllFRkJZaUI3bWp2cldPTUQxTVd5R0dWUjRiCkNjL3JNQjhHQTFVZEl3UVlNQmFBRkpCZ0s0NjYzVVdZMEhKbTVGb1plK1Rsem1mek1FY0dDQ3NHQVFVRkJ3RUIKQkRzd09UQTNCZ2dyQmdFRkJRY3dBb1lyYUhSMGNITTZMeTh4TWpjdU1DNHdMakU2T0RJd01DOTJNUzl3YTJrdApabXhoYm5RdGNtOXZkQzlqWVRBOUJnTlZIUjhFTmpBME1ES2dNS0F1aGl4b2RIUndjem92THpFeU55NHdMakF1Ck1UbzRNakF3TDNZeEwzQnJhUzFtYkdGdWRDMXliMjkwTDJOeWJEQUZCZ01yWlhBRFFRQnNOZWNUU0l6bmxvQWYKYkViU2JERlpGb20wMXc2WDN5WVpqVmFOQngrNEZmV3JNZ1ppU05rM3NkZ0dNRlpEVnVaZWl4OXlQUTk3bVIzWgpaTXU0Q3JRUAotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0t",
			"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNGVENDQWNlZ0F3SUJBZ0lVZElhblV0Nk0vNnFTL0RzMXJWSjZoc09JTmYwd0JRWURLMlZ3TUhneEN6QUoKQmdOVkJBWVRBbEpWTVE4d0RRWURWUVFJRXdaTmIzTmpiM2N4RHpBTkJnTlZCQWNUQmsxdmMyTnZkekVTTUJBRwpBMVVFQ2hNSlNsTkRJRVpzWVc1ME1SQXdEZ1lEVlFRTEV3ZEpibVp2YzJWak1TRXdId1lEVlFRREV4aEtVME1nClJteGhiblFnVW05dmRDQkRRU0JCTFRJd01qVXdIaGNOTWpVd056SXhNVE15TkRVMFdoY05ORFV3TnpFMk1UTXkKTlRJMFdqQjRNUXN3Q1FZRFZRUUdFd0pTVlRFUE1BMEdBMVVFQ0JNR1RXOXpZMjkzTVE4d0RRWURWUVFIRXdaTgpiM05qYjNjeEVqQVFCZ05WQkFvVENVcFRReUJHYkdGdWRERVFNQTRHQTFVRUN4TUhTVzVtYjNObFl6RWhNQjhHCkExVUVBeE1ZU2xORElFWnNZVzUwSUZKdmIzUWdRMEVnUVMweU1ESTFNQ293QlFZREsyVndBeUVBbGd1Q3hQRHUKV1VhajZjazZHdFIrZGdCNS9SRENSNmdhSWkzN3ZCQmx0ZE9qWXpCaE1BNEdBMVVkRHdFQi93UUVBd0lCQmpBUApCZ05WSFJNQkFmOEVCVEFEQVFIL01CMEdBMVVkRGdRV0JCU1FZQ3VPdXQxRm1OQnladVJhR1h2azVjNW44ekFmCkJnTlZIU01FR0RBV2dCU1FZQ3VPdXQxRm1OQnladVJhR1h2azVjNW44ekFGQmdNclpYQURRUUJxbTd5S21mVG0KV01PcFdHRldxSVJLcmJnRW44NkpyQmVWSXFXakVUMWs2NEVjR2pFN0JkdWxqdjdDVGhCQ2xwY1c3bzFuUGlVeApZeDFUNnMvSmU3b0kKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=",
			true,
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

func skipTestIfEnvironmentVariablesNotSet() {
	variables := []string{
		"TRANSIT_SECRET_ENGINE_PATH",
		"VAULT_ADDR",
		"VAULT_ROLE_ID",
		"VAULT_SECRET_ID",
	}

	for _, v := range variables {
		if os.Getenv(v) == "" {
			Skip(fmt.Sprintf("%s environment variable is not set", v))
		}
	}
}

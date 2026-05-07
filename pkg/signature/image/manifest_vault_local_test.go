package image_test

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sigstore/sigstore/pkg/cryptoutils"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signver"
	"github.com/deckhouse/delivery-kit-sdk/test/pkg/cert_utils"
	"github.com/deckhouse/delivery-kit-sdk/test/pkg/vault_server"
)

//go:embed testdata/jwt-policy.hcl
var jwtPolicyData []byte

var _ = Describe("manifest with real vault using local Vault server", Label("e2e", "local"), Serial, func() {
	DescribeTable("sign and verify image manifest one time using static auth token with VAULT_TOKEN",
		Serial,
		func(ctx SpecContext, keyType cert_utils.KeyType) {
			tmpDir := GinkgoT().TempDir()
			vaultServer := vault_server.NewVaultServer(tmpDir)
			vaultServer.Stop(ctx) // Ensure the server is stopped
			vaultServer.Start(ctx)
			defer vaultServer.Stop(ctx)
			vaultServer.Ready(ctx)

			certGen := cert_utils.GenerateCertificatesWithOptions(cert_utils.GenerateCertificatesOptions{
				KeyType:         keyType,
				PassFunc:        cryptoutils.SkipPassword,
				TmpDir:          tmpDir,
				NoIntermediates: true,
			})

			vaultTransitPath := "transit"
			vaultServer.EnableTransit(ctx, vaultTransitPath)

			vaultEndpoint := "endpoint"
			vaultServer.ImportTransitKey(ctx, vaultTransitPath, vaultEndpoint, cert_utils.FormatPrivateKeyToDERFile(tmpDir, certGen.PrivKey), vaultKeyType(keyType))

			GinkgoT().Setenv("TRANSIT_SECRET_ENGINE_PATH", vaultTransitPath)
			GinkgoT().Setenv("VAULT_ADDR", vaultServer.Addr.String())
			GinkgoT().Setenv("VAULT_TOKEN", vaultServer.RootToken)

			sv, err := signver.NewSignerVerifier(ctx, certGen.LeafRef, certGen.ChainRef, signver.KeyOpts{
				KeyRef:   fmt.Sprintf("hashivault://%s", vaultEndpoint),
				PassFunc: cryptoutils.SkipPassword,
			})
			Expect(err).To(Succeed())

			manifest := testSign(ctx, sv)
			testVerify(ctx, manifest, []string{certGen.RootRef})
		},
		Entry(
			"ECDSA_P256 key, without intermediates, root cert in chain, certs are file paths",
			cert_utils.KeyType_ECDSA_P256,
		),
		Entry(
			"ED25519 key, without intermediates, root cert in chain, certs are file paths",
			cert_utils.KeyType_ED25519,
		),
	)

	DescribeTable("sign and verify image manifest one time using per request auth with WERF_VAULT_AUTH_JWT",
		Serial,
		func(ctx SpecContext, keyType cert_utils.KeyType) {
			tmpDir := GinkgoT().TempDir()
			vaultServer := vault_server.NewVaultServer(tmpDir)
			vaultServer.Stop(ctx) // Ensure the server is stopped
			vaultServer.Start(ctx)
			defer vaultServer.Stop(ctx)
			vaultServer.Ready(ctx)

			certGen := cert_utils.GenerateCertificatesWithOptions(cert_utils.GenerateCertificatesOptions{
				KeyType:         keyType,
				PassFunc:        cryptoutils.SkipPassword,
				TmpDir:          tmpDir,
				NoIntermediates: true,
			})

			publicKeyFile := cert_utils.FormatPublicKeyToPEMFile(tmpDir, certGen.LeafCert.PublicKey)

			vaultServer.EnableAuthMethod(ctx, vault_server.AuthMethodJWT)

			vaultServer.ConfigureAuthMethod(ctx, vault_server.AuthMethodJWT, map[string]string{
				"jwt_validation_pubkeys": fmt.Sprintf(`@%s`, publicKeyFile),
				"jwt_supported_algs":     jwtAlgorithm(keyType),
			})

			policyName := "my-policy"
			policyReader := bytes.NewReader(jwtPolicyData)

			vaultServer.CreateOrUpdatePolicy(ctx, policyName, policyReader)

			jwtOptions := jwt.RegisteredClaims{
				Subject:   "my-service-account",
				Audience:  []string{"my-application"},
				NotBefore: jwt.NewNumericDate(time.Now()),
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
			}

			jwtRoleName := "my-role"
			vaultServer.CreateOrUpdateRole(ctx, vault_server.AuthMethodJWT, jwtRoleName, map[string]string{
				"bound_subject":   jwtOptions.Subject,
				"user_claim":      "sub",
				"bound_audiences": jwtOptions.Audience[0],
				"token_policies":  policyName,
			})

			vaultTransitPath := "transit"
			vaultServer.EnableTransit(ctx, vaultTransitPath)

			vaultEndpoint := "endpoint"
			vaultServer.ImportTransitKey(ctx, vaultTransitPath, vaultEndpoint, cert_utils.FormatPrivateKeyToDERFile(tmpDir, certGen.PrivKey), vaultKeyType(keyType))

			jwtToken := jwt.NewWithClaims(jwtSigningMethod(keyType), jwtOptions) // sub is the default claim
			jwtTokenStr, err := jwtToken.SignedString(certGen.PrivKey)
			Expect(err).To(Succeed())

			GinkgoT().Setenv("TRANSIT_SECRET_ENGINE_PATH", vaultTransitPath)
			GinkgoT().Setenv("VAULT_ADDR", vaultServer.Addr.String())
			GinkgoT().Setenv("WERF_VAULT_AUTH_JWT", jwtTokenStr)
			GinkgoT().Setenv("WERF_VAULT_AUTH_ROLE", jwtRoleName)

			sv, err := signver.NewSignerVerifier(ctx, certGen.LeafRef, certGen.ChainRef, signver.KeyOpts{
				KeyRef:   fmt.Sprintf("hashivault://%s", vaultEndpoint),
				PassFunc: cryptoutils.SkipPassword,
			})
			Expect(err).To(Succeed())

			manifest := testSign(ctx, sv)
			testVerify(ctx, manifest, []string{certGen.RootRef})
		},
		Entry(
			"ECDSA_P256 key, without intermediates, root cert in chain, certs are file paths",
			cert_utils.KeyType_ECDSA_P256,
		),
		Entry(
			"ED25519 key, without intermediates, root cert in chain, certs are file paths",
			cert_utils.KeyType_ED25519,
		),
	)

	// This test runs on GitHub CI and uses the real GitHub OIDC endpoint
	// (ACTIONS_ID_TOKEN_REQUEST_URL) to obtain a fresh JWT for Vault authentication.
	// A local Vault server is configured with OIDC discovery pointing to GitHub,
	// enabling end-to-end verification of the Actions OIDC Provider.
	DescribeTable("sign and verify image manifest using per request auth with WERF_ACTIONS_AUDIENCE on GitHub CI",
		Serial,
		func(ctx SpecContext, keyType cert_utils.KeyType) {
			if os.Getenv("CI") != "true" ||
				os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL") == "" ||
				os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN") == "" {
				Skip("Skipped because CI=false or ACTIONS_ID_TOKEN_REQUEST_URL/TOKEN is not set")
			}

			tmpDir := GinkgoT().TempDir()
			vaultServer := vault_server.NewVaultServer(tmpDir)
			vaultServer.Stop(ctx) // Ensure the server is stopped
			vaultServer.Start(ctx)
			defer vaultServer.Stop(ctx)
			vaultServer.Ready(ctx)

			certGen := cert_utils.GenerateCertificatesWithOptions(cert_utils.GenerateCertificatesOptions{
				KeyType:         keyType,
				PassFunc:        cryptoutils.SkipPassword,
				TmpDir:          tmpDir,
				NoIntermediates: true,
			})

			vaultServer.EnableAuthMethod(ctx, vault_server.AuthMethodJWT)

			// Configure Vault JWT auth to use GitHub's OIDC discovery URL.
			// This allows Vault to automatically fetch GitHub's public keys
			// and validate OIDC tokens issued by GitHub Actions.
			vaultServer.ConfigureAuthMethod(ctx, vault_server.AuthMethodJWT, map[string]string{
				"oidc_discovery_url": "https://token.actions.githubusercontent.com",
			})

			audience := "github-access-aud"

			policyName := "my-policy"
			policyReader := bytes.NewReader(jwtPolicyData)

			vaultServer.CreateOrUpdatePolicy(ctx, policyName, policyReader)

			roleName := "my-role"
			vaultServer.CreateOrUpdateRole(ctx, vault_server.AuthMethodJWT, roleName, map[string]string{
				"bound_audiences": audience,
				"user_claim":      "sub",
				"token_policies":  policyName,
				"token_ttl":       "5m",
			})

			vaultTransitPath := "transit"
			vaultServer.EnableTransit(ctx, vaultTransitPath)

			vaultEndpoint := "endpoint"
			vaultServer.ImportTransitKey(ctx, vaultTransitPath, vaultEndpoint, cert_utils.FormatPrivateKeyToDERFile(tmpDir, certGen.PrivKey), vaultKeyType(keyType))

			GinkgoT().Setenv("TRANSIT_SECRET_ENGINE_PATH", vaultTransitPath)
			GinkgoT().Setenv("VAULT_ADDR", vaultServer.Addr.String())
			GinkgoT().Setenv("WERF_VAULT_AUTH_ROLE", roleName)
			GinkgoT().Setenv("WERF_ACTIONS_AUDIENCE", audience)

			sv, err := signver.NewSignerVerifier(ctx, certGen.LeafRef, certGen.ChainRef, signver.KeyOpts{
				KeyRef:   fmt.Sprintf("hashivault://%s", vaultEndpoint),
				PassFunc: cryptoutils.SkipPassword,
			})
			Expect(err).To(Succeed())

			manifest := testSign(ctx, sv)
			testVerify(ctx, manifest, []string{certGen.RootRef})
		},
		Entry(
			"ECDSA_P256 key, without intermediates, root cert in chain, certs are file paths",
			cert_utils.KeyType_ECDSA_P256,
		),
		Entry(
			"ED25519 key, without intermediates, root cert in chain, certs are file paths",
			cert_utils.KeyType_ED25519,
		),
	)
})

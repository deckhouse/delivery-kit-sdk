package image_test

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sigstore/sigstore/pkg/cryptoutils"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signver"
	"github.com/deckhouse/delivery-kit-sdk/test/pkg/cert_utils"
	"github.com/deckhouse/delivery-kit-sdk/test/pkg/vault_server"
)

//go:embed testdata/jwt-policy.hcl
var longtermJwtPolicyData []byte

var _ = Describe("longterm sign with real vault using local Vault server and WERF_ACTIONS_AUDIENCE", Label("e2e", "local", "longterm"), Serial, func() {
	DescribeTable("sign image manifest multiple times using per request auth with WERF_ACTIONS_AUDIENCE on GitHub CI",
		Serial,
		func(ctx SpecContext, keyType cert_utils.KeyType, vaultTokenTTL time.Duration, signingExperimentTimeout, signingExperiment, signingAttemptInterval time.Duration) {
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
			policyReader := bytes.NewReader(longtermJwtPolicyData)

			vaultServer.CreateOrUpdatePolicy(ctx, policyName, policyReader)

			roleName := "my-role"
			// Use a short token TTL (5 minutes) so that the Vault token expires
			// during the 10+ minute experiment, forcing a token refresh via the
			// GitHub OIDC JWT provider.
			vaultServer.CreateOrUpdateRole(ctx, vault_server.AuthMethodJWT, roleName, map[string]string{
				"bound_audiences": audience,
				"user_claim":      "sub",
				"token_policies":  policyName,
				"token_ttl":       vaultTokenTTL.String(),
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

			experimentStartedAt := time.Now()
			attempt := 1

			// Sign repeatedly for 10 minutes to verify that the Vault token
			// is refreshed correctly via the GitHub OIDC JWT provider when it expires.
			// The Vault role has token_ttl configured shorter than the experiment duration,
			// so at least one refresh should occur.
			Eventually(func() time.Duration {
				attemptStartedAt := time.Now()
				fmt.Printf("Signing %d ... ", attempt)
				testSign(ctx, sv)
				fmt.Printf("done (%s, %s).\n", time.Since(attemptStartedAt), time.Now().Format(time.TimeOnly))
				attempt++
				return time.Since(experimentStartedAt)
			}, signingExperimentTimeout, signingAttemptInterval).Should(BeNumerically(">=", signingExperiment))
		},
		Entry(
			"ECDSA_P256 key, without intermediates, root cert in chain, certs are file paths",
			cert_utils.KeyType_ECDSA_P256,
			time.Minute*5,
			time.Minute*11,
			time.Minute*10,
			time.Second*10,
		),
		Entry(
			"ED25519 key, without intermediates, root cert in chain, certs are file paths",
			cert_utils.KeyType_ED25519,
			time.Minute*5,
			time.Minute*11,
			time.Minute*10,
			time.Second*10,
		),
	)
})

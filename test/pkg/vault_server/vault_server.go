package vault_server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os/exec"
	"path/filepath"

	. "github.com/onsi/gomega"
	"github.com/samber/lo"
)

type VaultServer struct {
	RootToken string
	Addr      *url.URL
	MountDir  string
}

const (
	vaultImage       = "vault:1.13.3"
	vaultContainerID = "vault-test-container"
)

func NewVaultServer(mountDir string) *VaultServer {
	urlParsed, err := url.Parse("http://localhost:8200")
	Expect(err).To(Succeed())

	return &VaultServer{
		RootToken: "my-root-token",
		Addr:      urlParsed,
		MountDir:  mountDir,
	}
}

func (vs *VaultServer) Start(ctx context.Context) {
	// Pull the latest Vault image
	_, err := runCommand(ctx, "docker", nil, "pull", vaultImage)
	Expect(err).To(Succeed())

	// Create and start the Vault container
	_, err = runCommand(ctx, "docker", nil, "run", "-d", "--rm", "-e", fmt.Sprintf("VAULT_DEV_ROOT_TOKEN_ID=%s", vs.RootToken), "-e", fmt.Sprintf("VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:%s", vs.Addr.Port()), "-v", fmt.Sprintf("%s:%s:ro", vs.MountDir, vs.MountDir), "-p", fmt.Sprintf("%s:8200", vs.Addr.Port()), "--name", vaultContainerID, vaultImage, "server", "--dev")

	Expect(err).To(Succeed())
}

func (vs *VaultServer) Ready(ctx context.Context) {
	healthFunc := func() error {
		return vs.status(ctx)
	}
	Eventually(healthFunc, "60s", "1s").Should(Succeed())
}

func (vs *VaultServer) Stop(ctx context.Context) {
	out, err := runCommand(ctx, "docker", nil, "ps", "-a", "-q", "--filter", fmt.Sprintf("name=%s", vaultContainerID))
	Expect(err).To(Succeed())
	if out == "" {
		return
	}
	_, err = runCommand(ctx, "docker", nil, "stop", vaultContainerID)
	Expect(err).To(Succeed())
}

func (vs *VaultServer) EnableTransit(ctx context.Context, path string) {
	_, err := vs.exec(ctx, nil, "secrets", "enable", fmt.Sprintf("-path=%s/", path), "transit")
	Expect(err).To(Succeed())
}

func (vs *VaultServer) EnableAuthMethod(ctx context.Context, methodType AuthMethodType) {
	_, err := vs.exec(ctx, nil, "auth", "enable", fmt.Sprintf("-path=%s/", methodType.Path()), methodType.String())
	Expect(err).To(Succeed())
}

// ConfigureAuthMethod
// https://developer.hashicorp.com/vault/api-docs/auth/jwt#configure
func (vs *VaultServer) ConfigureAuthMethod(ctx context.Context, authMethodType AuthMethodType, desc map[string]string) {
	args := []string{
		"write",
		fmt.Sprintf("auth/%s/config", authMethodType.Path()),
	}

	switch authMethodType {
	case AuthMethodJWT:
		args = append(args, convDescToSlice(desc)...)
	default:
		panic(fmt.Sprintf("unsupported auth method type: %s", authMethodType))
	}

	_, err := vs.exec(ctx, nil, args...)
	Expect(err).To(Succeed())
}

func (vs *VaultServer) CreateOrUpdatePolicy(ctx context.Context, policyName string, policyReader io.Reader) {
	args := []string{
		"policy",
		"write",
		policyName,
		"-",
	}

	_, err := vs.exec(ctx, policyReader, args...)
	Expect(err).To(Succeed())
}

func (vs *VaultServer) CreateOrUpdateRole(ctx context.Context, authMethodType AuthMethodType, roleName string, desc map[string]string) {
	args := []string{
		"write",
		fmt.Sprintf("auth/%s/role/%s", authMethodType.Path(), roleName),
	}

	desc["role_type"] = authMethodType.String()

	switch authMethodType {
	case AuthMethodJWT:
		args = append(args, convDescToSlice(desc)...)
	default:
		panic(fmt.Sprintf("unsupported auth method type: %s", authMethodType))
	}

	_, err := vs.exec(ctx, nil, args...)
	Expect(err).To(Succeed())
}

// ImportTransitKey
// Import key. IMPORTANT: the key must be in {PKCS #8 ASN.1 DER} form.
// https://developer.hashicorp.com/vault/docs/secrets/transit#manual-process
// Vault Transit CLI Examples:
// https://developer.hashicorp.com/vault/docs/commands/transit#examples
// Bring your own key (BYOK)
// https://developer.hashicorp.com/vault/docs/secrets/transit#bring-your-own-key-byok
func (vs *VaultServer) ImportTransitKey(ctx context.Context, path, endpoint, keyFileName string, keyType TransitKeyType) {
	_, err := vs.exec(ctx, nil, "transit", "import", filepath.Join(path, "keys", endpoint), fmt.Sprintf("@%s", keyFileName), fmt.Sprintf("type=%s", keyType))
	Expect(err).To(Succeed())
}

func (vs *VaultServer) exec(ctx context.Context, stdin io.Reader, args ...string) (string, error) {
	cmdArgs := []string{
		"exec",
		"-e", fmt.Sprintf("VAULT_ADDR=%s", vs.Addr.String()),
		"-e", fmt.Sprintf("VAULT_TOKEN=%s", vs.RootToken),
		"-i", // use stdin
		vaultContainerID,
		"vault",
	}
	cmdArgs = append(cmdArgs, args...)
	return runCommand(ctx, "docker", stdin, cmdArgs...)
}

func (vs *VaultServer) status(ctx context.Context) error {
	_, err := vs.exec(ctx, nil, "status")
	return err
}

func runCommand(ctx context.Context, name string, stdin io.Reader, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != nil {
		cmd.Stdin = stdin
	}
	b, err := cmd.CombinedOutput()
	return string(b), errors.Join(context.Cause(ctx), buildError(b, err))
}

func buildError(b []byte, err error) error {
	if err == nil {
		return nil
	}
	return errors.New(string(b))
}

func convDescToSlice(desc map[string]string) []string {
	return lo.MapToSlice(desc, func(k, v string) string {
		return fmt.Sprintf("%s=%s", k, v)
	})
}

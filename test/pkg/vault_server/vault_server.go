package vault_server

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os/exec"
	"path/filepath"

	. "github.com/onsi/gomega"
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
	_, err := runCommand(ctx, "docker", "pull", vaultImage)
	Expect(err).To(Succeed())

	// Create and start the Vault container
	_, err = runCommand(ctx, "docker", "run", "-d", "--rm",
		"-e", fmt.Sprintf("VAULT_DEV_ROOT_TOKEN_ID=%s", vs.RootToken),
		"-e", fmt.Sprintf("VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:%s", vs.Addr.Port()),
		"-v", fmt.Sprintf("%s:%s:ro", vs.MountDir, vs.MountDir),
		"-p", fmt.Sprintf("%s:8200", vs.Addr.Port()),
		"--name", vaultContainerID,
		vaultImage,
		"server", "--dev")

	Expect(err).To(Succeed())
}

func (vs *VaultServer) Ready(ctx context.Context) {
	healthFunc := func() error {
		return vs.status(ctx)
	}
	Eventually(healthFunc, "60s", "1s").Should(Succeed())
}

func (vs *VaultServer) Stop(ctx context.Context) {
	out, err := runCommand(ctx, "docker", "ps", "-a", "-q", "--filter", fmt.Sprintf("name=%s", vaultContainerID))
	Expect(err).To(Succeed())
	if out == "" {
		return
	}
	_, err = runCommand(ctx, "docker", "stop", vaultContainerID)
	Expect(err).To(Succeed())
}

// EnableTransit Enable Transit Secrets Engine
func (vs *VaultServer) EnableTransit(ctx context.Context, path string) {
	_, err := vs.exec(ctx, "secrets", "enable", fmt.Sprintf("-path=%s/", path), "transit")
	Expect(err).To(Succeed())
}

func (vs *VaultServer) ImportTransitKey(ctx context.Context, path, endpoint, keyFileName string, keyType TransitKeyType) {
	_, err := vs.exec(ctx,
		"transit", "import",
		filepath.Join(path, "keys", endpoint),
		fmt.Sprintf("@%s", keyFileName),
		fmt.Sprintf("type=%s", keyType))
	Expect(err).To(Succeed())
}

func (vs *VaultServer) exec(ctx context.Context, args ...string) (string, error) {
	cmdArgs := []string{"exec", "-e", fmt.Sprintf("VAULT_ADDR=%s", vs.Addr.String()), "-e", fmt.Sprintf("VAULT_TOKEN=%s", vs.RootToken), vaultContainerID, "vault"}
	cmdArgs = append(cmdArgs, args...)
	return runCommand(ctx, "docker", cmdArgs...)
}

func (vs *VaultServer) status(ctx context.Context) error {
	_, err := vs.exec(ctx, "status")
	return err
}

func runCommand(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	b, err := cmd.CombinedOutput()
	return string(b), errors.Join(context.Cause(ctx), buildError(b, err))
}

func buildError(b []byte, err error) error {
	if err == nil {
		return nil
	}
	return errors.New(string(b))
}

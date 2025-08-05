package vault_server

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"

	. "github.com/onsi/gomega"
)

type VaultServer struct {
	RootToken string
	Addr      string
	MountDir  string
}

const (
	vaultImage       = "vault:1.13.3"
	vaultContainerID = "vault-test-container"
)

func NewVaultServer(mountDir string) *VaultServer {
	return &VaultServer{
		RootToken: "my-root-token",
		Addr:      "http://localhost:8200",
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
		"-e", "VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200",
		"-v", fmt.Sprintf("%s:%s:ro", vs.MountDir, vs.MountDir),
		"-p", "8200:8200",
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
	cmdArgs := []string{"exec", "-e", fmt.Sprintf("VAULT_ADDR=%s", vs.Addr), "-e", fmt.Sprintf("VAULT_TOKEN=%s", vs.RootToken), vaultContainerID, "vault"}
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
	return string(b), err
}

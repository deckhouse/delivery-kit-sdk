package integrity

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"

	"github.com/deckhouse/delivery-kit-sdk/internal/exec"
)

const (
	AnnoNameBuildTimestamp   = "io.deckhouse.delivery-kit.build-timestamp"
	AnnoNameDMVerityRootHash = "io.deckhouse.delivery-kit.dm-verity-root-hash"

	staticMkfsBuildTimestamp = "1750791050" // 2025-06-24T18:50:50Z
	magicVeritySalt          = "dc0f616e4bf75776061d5ffb7a6f45e1313b7cc86f3aa49b68de4f6d187bad2b"
)

func CalculateImageDMVerityAnnotations(ctx context.Context, img v1.Image) (map[string]string, error) {
	rootHash, err := CalculateImageDMVerityRootHash(ctx, img)
	if err != nil {
		return nil, err
	}

	return map[string]string{
		AnnoNameBuildTimestamp:   staticMkfsBuildTimestamp,
		AnnoNameDMVerityRootHash: rootHash,
	}, nil
}

func CalculateLayerDMVerityAnnotations(ctx context.Context, layer v1.Layer) (map[string]string, error) {
	rootHash, err := CalculateLayerDMVerityRootHash(ctx, layer)
	if err != nil {
		return nil, err
	}

	return map[string]string{
		AnnoNameBuildTimestamp:   staticMkfsBuildTimestamp,
		AnnoNameDMVerityRootHash: rootHash,
	}, nil
}

func CalculateImageDMVerityRootHash(ctx context.Context, img v1.Image) (string, error) {
	rc := mutate.Extract(img)
	defer rc.Close()

	return CalculateDMVerityRootHash(ctx, rc)
}

func CalculateLayerDMVerityRootHash(ctx context.Context, layer v1.Layer) (string, error) {
	rc, err := layer.Uncompressed()
	if err != nil {
		return "", err
	}
	defer rc.Close()

	return CalculateDMVerityRootHash(ctx, rc)
}

func CalculateDMVerityRootHash(ctx context.Context, rc io.Reader) (string, error) {
	tmpDir, err := createTempDir("layer-erofs")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmpDir)

	erofsPath := filepath.Join(tmpDir, "layer.erofs.img")
	hashPath := filepath.Join(tmpDir, "layer.hash.img")

	if err := createErofsImage(ctx, rc, erofsPath, staticMkfsBuildTimestamp); err != nil {
		return "", fmt.Errorf("create EROFS image: %w", err)
	}

	if err := createHashImageFile(ctx, erofsPath, hashPath); err != nil {
		return "", fmt.Errorf("create hash image: %w", err)
	}

	rootHash, err := getVeritySetupFormatRootHash(ctx, erofsPath, hashPath)
	if err != nil {
		return "", fmt.Errorf("get verity setup format root hash: %w", err)
	}

	return rootHash, nil
}

// ComputeVerityRootHashForLayerFile returns the root hash for the hash tree of the `layerFile`.
// Files passed mut be present on the filesystem.
func ComputeVerityRootHashForLayerFile(ctx context.Context, layerFile, hashTreeFile string) (string, error) {
	if _, err := os.Stat(layerFile); err != nil {
		return "", fmt.Errorf("validate layer path: %w", err)
	}

	if _, err := os.Stat(hashTreeFile); err != nil {
		return "", fmt.Errorf("validate hash tree path: %w", err)
	}

	rootHash, err := getVeritySetupFormatRootHash(ctx, layerFile, hashTreeFile)
	if err != nil {
		return "", fmt.Errorf("calculate root hash: %w", err)
	}

	return rootHash, nil
}

func createTempDir(prefix string) (string, error) {
	tmpDir, err := os.MkdirTemp("", prefix)
	if err != nil {
		return "", fmt.Errorf("create temp dir: %w", err)
	}
	return tmpDir, nil
}

func validateMkfsVersion(ctx context.Context) error {
	versionOutput, err := runCommand(ctx, "mkfs.erofs", "--version")
	var versionMatch string
	if err != nil {
		versionMatch = fmt.Sprintf("undefined (error: %v)", err)
	} else {
		versionRegex := regexp.MustCompile(`\d+\.\d+\.\d+`)
		versionMatch = versionRegex.FindString(versionOutput)
		if versionMatch == "" {
			versionMatch = "undefined"
		}
	}

	requiredVersion := "1.8.10"
	if versionMatch != requiredVersion {
		return fmt.Errorf("mkfs.erofs version %s does not match the required version %s", versionMatch, requiredVersion)
	}

	return nil
}

func CreateErofsImage(ctx context.Context, rc io.Reader, erofsPath, mkfsBuildTimestamp string) error {
	return createErofsImage(ctx, rc, erofsPath, mkfsBuildTimestamp)
}

func createErofsImage(ctx context.Context, rc io.Reader, erofsPath, mkfsBuildTimestamp string) error {
	if err := validateMkfsVersion(ctx); err != nil {
		return err
	}

	mkfs := exec.CommandContextCancellation(ctx, "mkfs.erofs", "-Uclear", "-T"+mkfsBuildTimestamp, "-x-1", "-Enoinline_data", "--aufs", "--tar=-", erofsPath)
	mkfs.Stderr = os.Stderr
	mkfs.Stdin = rc

	if err := mkfs.Run(); err != nil {
		return fmt.Errorf("mkfs.erofs: %w", err)
	}
	return nil
}

func CreateHashImageFile(ctx context.Context, erofsPath, hashPath string) error {
	err := createHashImageFile(ctx, erofsPath, hashPath)
	if err != nil {
		return fmt.Errorf("create image file: %w", err)
	}

	_, err = getVeritySetupFormatRootHash(ctx, erofsPath, hashPath)
	if err != nil {
		return fmt.Errorf("format image file: %w", err)
	}

	return nil
}

func createHashImageFile(_ context.Context, erofsPath, hashPath string) error {
	stat, err := os.Stat(erofsPath)
	if err != nil {
		return fmt.Errorf("stat erofs image: %w", err)
	}

	size := stat.Size()

	// Verity partition (LABEL=VERITY), should require 8-10% the size of Root.
	hashSize := int64(float64(size) * 0.1)
	if hashSize < 4*1024*1024 {
		hashSize = 4 * 1024 * 1024
	}

	file, err := os.Create(hashPath)
	if err != nil {
		return fmt.Errorf("create hash image file: %w", err)
	}
	defer file.Close()

	if err := file.Truncate(hashSize); err != nil {
		return fmt.Errorf("truncate hash image file: %w", err)
	}

	return nil
}

func getVeritySetupFormatRootHash(ctx context.Context, erofsPath, hashPath string) (string, error) {
	output, err := runCommand(ctx, "veritysetup", "format", "--data-block-size=4096", "--hash-block-size=4096", "--salt="+magicVeritySalt, erofsPath, hashPath)
	if err != nil {
		return "", fmt.Errorf("veritysetup: %v\n%s", err, output)
	}

	rootHash := extractRootHash(output)
	if rootHash == "" {
		return "", fmt.Errorf("failed to extract root hash")
	}
	return rootHash, nil
}

func runCommand(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContextCancellation(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), err
	}
	return string(out), nil
}

func extractRootHash(output string) string {
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "Root hash:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Root hash:"))
		}
	}
	return ""
}

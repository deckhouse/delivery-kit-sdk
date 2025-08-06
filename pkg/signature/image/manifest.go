package image

import (
	"context"
	"crypto/sha256"
	"fmt"
	"slices"
	"strconv"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/samber/lo"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signature"
	"github.com/deckhouse/delivery-kit-sdk/pkg/signver"
)

func GetSignatureAnnotationsForImageManifest(ctx context.Context, sv *signver.SignerVerifier, manifest *v1.Manifest) (map[string]string, error) {
	payload, err := getManifestPayloadHash(manifest)
	if err != nil {
		return nil, fmt.Errorf("getting manifest payload hash: %w", err)
	}

	bundle, err := signature.Sign(ctx, sv, payload)
	if err != nil {
		return nil, fmt.Errorf("signing image payload: %w", err)
	}

	annotations, err := bundle.ToMap()
	if err != nil {
		return nil, fmt.Errorf("bundle to map convertation: %w", err)
	}

	return annotations, nil
}

func VerifyImageManifestSignature(ctx context.Context, rootCertRef string, manifest *v1.Manifest) error {
	bundle, err := signature.NewBundleFromMap(manifest.Annotations)
	if err != nil {
		return fmt.Errorf("signature bundle creation: %w", err)
	}

	payload, err := getManifestPayloadHash(manifest)
	if err != nil {
		return fmt.Errorf("getting manifest payload hash: %w", err)
	}

	if err = signature.VerifyBundle(ctx, bundle, payload, rootCertRef); err != nil {
		return fmt.Errorf("bundle verification: %w", err)
	}

	return nil
}

func getManifestPayloadHash(manifest *v1.Manifest) (string, error) {
	var hashes []string
	hashes = append(hashes, strconv.FormatInt(manifest.SchemaVersion, 10), string(manifest.MediaType))
	hashes = append(hashes, manifest.Config.Digest.String(), string(manifest.Config.MediaType), strconv.FormatInt(manifest.Config.Size, 10))

	for _, layer := range manifest.Layers {
		hashes = append(hashes, layer.Digest.String(), string(layer.MediaType), strconv.FormatInt(layer.Size, 10))
	}

	// Filter out keys of signature bundle
	bundleAnnotations, err := signature.NewEmptyBundle().ToMap()
	if err != nil {
		return "", fmt.Errorf("empty bundle to map convertation: %w", err)
	}
	annotations := lo.OmitByKeys(manifest.Annotations, lo.Keys(bundleAnnotations))

	keys := lo.Keys(annotations)
	slices.Sort(keys)

	for _, k := range keys {
		hashes = append(hashes, k, annotations[k])
	}

	return fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(hashes, "")))), nil
}

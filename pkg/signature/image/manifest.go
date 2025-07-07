package image

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signature"
	"github.com/deckhouse/delivery-kit-sdk/pkg/signver"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/samber/lo"
)

func GetSignatureAnnotationsForImageManifest(_ context.Context, sv *signver.SignerVerifier, manifest *v1.Manifest) (map[string]string, error) {
	signedPayload, err := sv.SignMessage(strings.NewReader(getManifestPayloadHash(manifest)))
	if err != nil {
		return nil, err
	}

	sigBundle := signature.NewBundle(signedPayload, sv.Cert, sv.Chain)
	return bundleToAnnotations(sigBundle), nil
}

func VerifyImageManifestSignature(ctx context.Context, rootCertRef string, manifest *v1.Manifest) error {
	sigBundle, err := newBundleFromAnnotations(manifest.Annotations)
	if err != nil {
		return fmt.Errorf("signature bundle creation: %w", err)
	}

	if _, _, err = signver.VerifyChain(sigBundle.Cert.Base64String(), sigBundle.Chain.Base64String(), rootCertRef); err != nil {
		return fmt.Errorf("cert verification: %w", err)
	}

	verifier, err := signver.NewVerifierFromCert(ctx, sigBundle.Cert.Base64String())
	if err != nil {
		return fmt.Errorf("verifier creation: %w", err)
	}

	signatureReader := bytes.NewReader(sigBundle.Signature)
	messageReader := strings.NewReader(getManifestPayloadHash(manifest))

	if err = verifier.VerifySignature(signatureReader, messageReader); err != nil {
		return fmt.Errorf("image signature verification: %w", err)
	}

	return nil
}

func getManifestPayloadHash(manifest *v1.Manifest) string {
	var hashes []string
	hashes = append(hashes, strconv.FormatInt(manifest.SchemaVersion, 10), string(manifest.MediaType))

	// FIXME: The following line is commented out because the Config.Digest has changed after mutating
	// the annotations of the manifest. This requires investigation.
	// hashes = append(hashes, manifest.Config.Digest.String(), string(manifest.Config.MediaType), strconv.FormatInt(manifest.Config.Size, 10))

	for _, layer := range manifest.Layers {
		hashes = append(hashes, layer.Digest.String(), string(layer.MediaType), strconv.FormatInt(layer.Size, 10))
	}

	annotations := safeAnnotations(manifest.Annotations)
	keys := lo.Keys(annotations)
	slices.Sort(keys)

	for _, k := range keys {
		hashes = append(hashes, k, annotations[k])
	}

	return fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(hashes, ""))))
}

package image

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sort"
	"strconv"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	
	"github.com/deckhouse/delivery-kit-sdk/pkg/signver"
)

const (
	annoNameSignature       = "io.deckhouse.deliverykit.signature"
	annoNameCert            = "io.deckhouse.deliverykit.cert"
	annoNameChain           = "io.deckhouse.deliverykit.chain"
)

func GetSignatureAnnotationsForImageManifest(_ context.Context, sv *signver.SignerVerifier, manifest *v1.Manifest) (map[string]string, error) {
	signedPayload, err := sv.SignMessage(strings.NewReader(getManifestPayloadHash(manifest)))
	if err != nil {
		return nil, err
	}
	
	annotations := make(map[string]string)
	annotations[annoNameSignature] = base64.StdEncoding.EncodeToString(signedPayload)
	if sv.Cert != nil {
		annotations[annoNameCert] = base64.StdEncoding.EncodeToString(sv.Cert)
	}
	if sv.Chain != nil {
		annotations[annoNameChain] = base64.StdEncoding.EncodeToString(sv.Chain)
	}
	
	return annotations, nil
}

func VerifyImageManifestSignature(_ context.Context, sv *signver.SignerVerifier, manifest *v1.Manifest) error {
	panic("not implemented yet")
}

func getManifestPayloadHash(manifest *v1.Manifest) string {
	annotations := manifest.Annotations
	if annotations == nil {
		annotations = make(map[string]string, 3)
	}

	var hashes []string
	hashes = append(hashes, strconv.FormatInt(manifest.SchemaVersion, 10), string(manifest.MediaType))
	hashes = append(hashes, manifest.Config.Digest.String(), string(manifest.Config.MediaType), strconv.FormatInt(manifest.Config.Size, 10))
	for _, layer := range manifest.Layers {
		hashes = append(hashes, layer.Digest.String(), string(layer.MediaType), strconv.FormatInt(layer.Size, 10))
	}

	keys := sortedKeys(annotations)
	for _, k := range keys {
		if k == annoNameSignature || k == annoNameCert || k == annoNameChain {
			continue
		}
		hashes = append(hashes, k, annotations[k])
	}
	
	return fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(hashes, ""))))
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
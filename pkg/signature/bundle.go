package signature

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signver"
)

var (
	ErrNoSignature      = errors.New("no signature")
	ErrNoCert           = errors.New("no cert")
	ErrCertRequired     = errors.New("cert required")
	ErrRootCertRequired = errors.New("root cert required")
)

type Base64Bytes []byte

func (b Base64Bytes) Base64String() string {
	return base64.StdEncoding.EncodeToString(b)
}

type Bundle struct {
	Signature Base64Bytes `json:"io.deckhouse.delivery-kit.signature"`
	Cert      Base64Bytes `json:"io.deckhouse.delivery-kit.cert"`
	Chain     Base64Bytes `json:"io.deckhouse.delivery-kit.chain"`
}

func (b Bundle) ToMap() (map[string]string, error) {
	data, err := json.Marshal(b)
	if err != nil {
		return nil, fmt.Errorf("marshaling bundle to json: %w", err)
	}

	var result map[string]string
	if err = json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("unmarshaling json to map: %w", err)
	}

	return result, nil
}

type rawBundle Bundle

func (b *Bundle) UnmarshalJSON(data []byte) error {
	var raw rawBundle
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	*b = Bundle(raw)

	if b.Signature == nil {
		return ErrNoSignature
	}
	if b.Cert == nil {
		return ErrNoCert
	}

	return nil
}

func NewBundleFromMap(m map[string]string) (Bundle, error) {
	data, err := json.Marshal(m)
	if err != nil {
		return Bundle{}, fmt.Errorf("marshaling map to []byte: %w", err)
	}

	var b Bundle
	if err = json.Unmarshal(data, &b); err != nil {
		return Bundle{}, fmt.Errorf("unmarshaling map to bundle: %w", err)
	}

	return b, nil
}

func NewEmptyBundle() Bundle {
	return Bundle{
		Signature: make([]byte, 0),
		Cert:      make([]byte, 0),
		Chain:     make([]byte, 0),
	}
}

func Sign(_ context.Context, sv *signver.SignerVerifier, payload string) (Bundle, error) {
	signedPayload, err := sv.SignMessage(strings.NewReader(payload))
	if err != nil {
		return Bundle{}, fmt.Errorf("signing payload: %w", err)
	}

	if sv.Cert == nil {
		return Bundle{}, ErrCertRequired
	}

	return Bundle{
		Signature: signedPayload,
		Cert:      sv.Cert,
		Chain:     sv.Chain,
	}, nil
}

func VerifyBundle(ctx context.Context, bundle Bundle, payload string, rootCertRefs []string) error {
	if err := verifyChainWithAnyRoot(bundle.Cert.Base64String(), bundle.Chain.Base64String(), rootCertRefs); err != nil {
		return fmt.Errorf("verifying chain: %w", err)
	}

	verifier, err := signver.NewVerifierFromCert(ctx, bundle.Cert.Base64String())
	if err != nil {
		return fmt.Errorf("verifier creation: %w", err)
	}

	signatureReader := bytes.NewReader(bundle.Signature)
	messageReader := strings.NewReader(payload)

	if err = verifier.VerifySignature(signatureReader, messageReader); err != nil {
		return fmt.Errorf("signature verification: %w", err)
	}

	return nil
}

// verifyChainWithAnyRoot checks chain verification with any root certificate
func verifyChainWithAnyRoot(certRef, chainRef string, rootRefs []string) error {
	if len(rootRefs) == 0 {
		return ErrRootCertRequired
	}

	verificationErrors := make([]error, 0, len(rootRefs))

	for i, rootRef := range rootRefs {
		_, newChainRef, err := signver.ConcatChain(chainRef, rootRef)
		if err != nil {
			return fmt.Errorf("building certificate chain[%d]: %w", i, err)
		}

		if _, _, err = signver.VerifyChain(certRef, newChainRef); err != nil {
			verificationErrors = append(verificationErrors, fmt.Errorf("chain verification[%d]: %w", i, err))
		} else {
			return nil
		}
	}

	return errors.Join(verificationErrors...)
}

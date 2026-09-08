package inhouse

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/deckhouse/elfedit"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signature"
	"github.com/deckhouse/delivery-kit-sdk/pkg/signver"
)

func SignBytes(ctx context.Context, signerVerifier *signver.SignerVerifier, image []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	f, err := readELF(ctx, bytes.NewReader(image), int64(len(image)))
	if err != nil {
		return nil, err
	}
	digest, err := f.hash(ctx)
	if err != nil {
		return nil, fmt.Errorf("hash ELF: %w", err)
	}
	bundle, err := signature.Sign(ctx, signerVerifier, digest)
	if err != nil {
		return nil, fmt.Errorf("sign bundle: %w", err)
	}
	payload, err := json.Marshal(bundle)
	if err != nil {
		return nil, fmt.Errorf("marshal signature bundle: %w", err)
	}
	note, err := makeNote(f.order, payload)
	if err != nil {
		return nil, err
	}

	limit := uint64(len(image)) + 2*maxMetadataSize + uint64(len(note)) + 4096
	signed, err := elfedit.SetSection(ctx, image, signatureSectionName, note, elfedit.SectionOptions{
		Type: elf.SHT_NOTE, Alignment: 4, MaxOutputSize: limit,
	})
	if err != nil {
		return nil, fmt.Errorf("write signature section: %w", err)
	}
	updated, err := readELF(ctx, bytes.NewReader(signed), int64(len(signed)))
	if err != nil {
		return nil, fmt.Errorf("read signed ELF: %w", err)
	}
	updatedDigest, err := updated.hash(ctx)
	if err != nil {
		return nil, fmt.Errorf("hash signed ELF: %w", err)
	}
	if updatedDigest != digest {
		return nil, fmt.Errorf("signature edit changed ELF digest")
	}
	stored, err := updated.signature()
	if err != nil {
		return nil, fmt.Errorf("read written signature: %w", err)
	}
	if !bytes.Equal(stored, payload) {
		return nil, fmt.Errorf("written signature differs from signed bundle")
	}

	return signed, nil
}

func VerifyBytes(ctx context.Context, rootCertRefs []string, image []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	f, err := readELF(ctx, bytes.NewReader(image), int64(len(image)))
	if err != nil {
		return err
	}
	return verifyELF(ctx, rootCertRefs, f)
}

func verifyELF(ctx context.Context, rootCertRefs []string, f *elfFile) error {
	payload, err := f.signature()
	if err != nil {
		return err
	}
	var bundle *signature.Bundle
	if err := json.Unmarshal(payload, &bundle); err != nil {
		return fmt.Errorf("unmarshal signature bundle: %w", err)
	}
	if bundle == nil {
		return errors.New("signature bundle is null")
	}
	digest, err := f.hash(ctx)
	if err != nil {
		return fmt.Errorf("hash ELF: %w", err)
	}
	verifyErr := signature.VerifyBundle(ctx, *bundle, digest, rootCertRefs)
	if verifyErr == nil {
		return nil
	}

	// Legacy digests used the signer's native byte order, with no order marker.
	var otherOrder binary.ByteOrder = binary.BigEndian
	if binary.NativeEndian.Uint16([]byte{1, 0}) != 1 {
		otherOrder = binary.LittleEndian
	}
	otherDigest, err := f.hashOrder(ctx, otherOrder)
	if err != nil {
		return fmt.Errorf("hash ELF in alternate legacy order: %w", err)
	}
	if err := signature.VerifyBundle(ctx, *bundle, otherDigest, rootCertRefs); err != nil {
		return fmt.Errorf("verify signature bundle: %w", errors.Join(verifyErr, err))
	}
	return nil
}

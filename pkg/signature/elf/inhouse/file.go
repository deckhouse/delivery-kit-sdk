package inhouse

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/deckhouse/elfedit"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signature"
	"github.com/deckhouse/delivery-kit-sdk/pkg/signver"
)

func Sign(ctx context.Context, signerVerifier *signver.SignerVerifier, path string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("resolve ELF path: %w", err)
	}
	src, info, err := openRegularFile(resolved)
	if err != nil {
		return err
	}
	defer src.Close()
	f, err := readELF(ctx, src, info.Size())
	if err != nil {
		return err
	}
	digest, err := f.hash(ctx)
	if err != nil {
		return fmt.Errorf("hash ELF: %w", err)
	}
	bundle, err := signature.Sign(ctx, signerVerifier, digest)
	if err != nil {
		return fmt.Errorf("sign bundle: %w", err)
	}
	payload, err := json.Marshal(bundle)
	if err != nil {
		return fmt.Errorf("marshal signature bundle: %w", err)
	}
	note, err := makeNote(f.order, payload)
	if err != nil {
		return err
	}
	dst, err := os.CreateTemp(filepath.Dir(resolved), ".delivery-kit-sign-*")
	if err != nil {
		return fmt.Errorf("create signed ELF: %w", err)
	}
	defer os.Remove(dst.Name())
	defer dst.Close()
	// The budget covers copied names, a new table and small alignment padding.
	// Metadata is bounded separately before either parser allocates it.
	limit := uint64(info.Size()) + 2*maxMetadataSize + uint64(len(note)) + 4096
	if err := elfedit.WriteSection(ctx, dst, src, info.Size(), signatureSectionName, note, elfedit.SectionOptions{
		Type: elf.SHT_NOTE, Alignment: 4, MaxOutputSize: limit,
	}); err != nil {
		return fmt.Errorf("write signature section: %w", err)
	}
	updatedInfo, err := dst.Stat()
	if err != nil {
		return fmt.Errorf("stat signed ELF: %w", err)
	}
	updated, err := readELF(ctx, dst, updatedInfo.Size())
	if err != nil {
		return fmt.Errorf("read signed ELF: %w", err)
	}
	updatedDigest, err := updated.hash(ctx)
	if err != nil {
		return fmt.Errorf("hash signed ELF: %w", err)
	}
	if updatedDigest != digest {
		return fmt.Errorf("signature edit changed ELF digest")
	}
	stored, err := updated.signature()
	if err != nil {
		return fmt.Errorf("read written signature: %w", err)
	}
	if !bytes.Equal(stored, payload) {
		return fmt.Errorf("written signature differs from signed bundle")
	}
	if err := preserveOwnership(dst, info); err != nil {
		return err
	}
	if err := preservePermissionsAndAttributes(ctx, src, dst, info.Mode()); err != nil {
		return fmt.Errorf("preserve ELF extended attributes: %w", err)
	}
	finalInfo, err := dst.Stat()
	if err != nil {
		return fmt.Errorf("stat final ELF: %w", err)
	}
	if finalInfo.Mode() != info.Mode() {
		return fmt.Errorf("extended attribute edit changed ELF permissions")
	}
	if err := dst.Sync(); err != nil {
		return fmt.Errorf("sync signed ELF: %w", err)
	}
	if err := dst.Close(); err != nil {
		return fmt.Errorf("close signed ELF: %w", err)
	}
	current, err := os.Stat(resolved)
	if err != nil {
		return fmt.Errorf("stat original ELF: %w", err)
	}
	if !os.SameFile(info, current) || info.Size() != current.Size() || !info.ModTime().Equal(current.ModTime()) {
		return fmt.Errorf("original ELF changed during signing")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Rename(dst.Name(), resolved); err != nil {
		return fmt.Errorf("replace ELF: %w", err)
	}
	return nil
}

func Verify(ctx context.Context, rootCertRefs []string, path string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	src, info, err := openRegularFile(path)
	if err != nil {
		return err
	}
	defer src.Close()
	f, err := readELF(ctx, src, info.Size())
	if err != nil {
		return err
	}
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

func openRegularFile(path string) (*os.File, os.FileInfo, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("stat ELF: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("ELF requires a regular file")
	}
	src, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open ELF: %w", err)
	}
	info, err = src.Stat()
	if err != nil {
		return nil, nil, errors.Join(fmt.Errorf("stat opened ELF: %w", err), src.Close())
	}
	if !info.Mode().IsRegular() {
		return nil, nil, errors.Join(fmt.Errorf("ELF requires a regular file"), src.Close())
	}
	return src, info, nil
}

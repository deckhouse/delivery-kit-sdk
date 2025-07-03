package elf_test

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signature/elf"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sigstore/sigstore/pkg/signature"
)

const helloElfFile = "../../../test/data/hello.elf"
const helloElfFileWithSignature = "../../../test/data/hello_with_signature.elf"

var _ = Describe("signature/elf", func() {
	DescribeTable("should add new signature",
		func(ctx SpecContext) {
			signerVerifier := &fakeSignerVerifier{}

			oldElfData, err := os.ReadFile(helloElfFile)
			Expect(err).To(Succeed())

			newElfFile, err := os.CreateTemp("", "hello.*.elf")
			Expect(err).To(Succeed())
			defer newElfFile.Close()
			// defer os.Remove(newElfFile.Name())

			_, err = newElfFile.Write(oldElfData)
			Expect(err).To(Succeed())

			newElfFilePath := newElfFile.Name()
			Expect(newElfFile.Close()).To(Succeed())

			Expect(elf.Sign(ctx, signerVerifier, newElfFilePath)).To(Succeed())

			_, err = os.ReadFile(newElfFilePath)
			Expect(err).To(Succeed())

			// fixtureNewElfData, err := os.ReadFile(helloElfFileWithSignature)
			// Expect(err).To(Succeed())
			//
			// Expect(newElfData).To(Equal(fixtureNewElfData))
		},
		Entry(
			"with x509 certs",
		),
	)
	DescribeTable("should update outdated signature",
		func(ctx SpecContext) {
		},
		Entry(
			"with x509 certs",
		),
	)
	DescribeTable("should verify signature",
		func(ctx SpecContext) {
		},
		Entry(
			"with x509 certs",
		),
	)
	DescribeTable("should fail to verify signature because wrong signature",
		func(ctx SpecContext) {
		},
		Entry(
			"with x509 certs",
		),
	)
	DescribeTable("should fail to verify signature because no signature",
		func(ctx SpecContext) {
		},
		Entry(
			"with x509 certs",
		),
	)
})

type fakeSignerVerifier struct{}

func (s *fakeSignerVerifier) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	return []byte(strings.Repeat("0", 32)), nil
}

func (s *fakeSignerVerifier) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	msg, err := io.ReadAll(message)
	if err != nil {
		return nil, err
	}

	result := make([]byte, base64.StdEncoding.EncodedLen(len(msg)))
	base64.StdEncoding.Encode(msg, result)

	return result, nil
}

func (s *fakeSignerVerifier) VerifySignature(signature, message io.Reader, opts ...signature.VerifyOption) error {
	sig, err := io.ReadAll(signature)
	if err != nil {
		return err
	}

	msg, err := io.ReadAll(message)
	if err != nil {
		return err
	}

	newSig := make([]byte, base64.StdEncoding.EncodedLen(len(msg)))
	base64.StdEncoding.Encode(msg, newSig)

	if !bytes.Equal(sig, newSig) {
		return fmt.Errorf("signatures don't match")
	}

	return nil
}

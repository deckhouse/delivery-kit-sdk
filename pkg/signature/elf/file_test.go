//go:build linux
// +build linux

package elf_test

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signature/elf"
	"github.com/deckhouse/delivery-kit-sdk/pkg/signver"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sigstore/sigstore/pkg/signature"
)

const helloElfFile = "../../../test/data/hello.elf"
const helloElfFileWithSignature = "../../../test/data/hello_with_signature.elf"

var _ = Describe("signature/elf", func() {
	DescribeTable("should add new signature",
		func(ctx SpecContext) {
			// FIXME(ilya-lesikov):
			signerVerifier := signver.NewSignerVerifier(context.Background())

			oldElfData, err := os.ReadFile(helloElfFile)
			Expect(err).To(Succeed())

			newElfFile, err := os.CreateTemp("", "hello.*.elf")
			Expect(err).To(Succeed())
			defer newElfFile.Close()
			defer os.Remove(newElfFile.Name())

			_, err = newElfFile.Write(oldElfData)
			Expect(err).To(Succeed())

			newElfFilePath := newElfFile.Name()
			Expect(newElfFile.Close()).To(Succeed())

			Expect(elf.Sign(ctx, signerVerifier, newElfFilePath)).To(Succeed())

			newElfData, err := os.ReadFile(newElfFilePath)
			Expect(err).To(Succeed())

			fixtureNewElfData, err := os.ReadFile(helloElfFileWithSignature)
			Expect(err).To(Succeed())

			Expect(newElfData).To(Equal(fixtureNewElfData))
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

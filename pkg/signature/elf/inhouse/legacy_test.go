package inhouse_test

import (
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"

	g "github.com/onsi/ginkgo/v2"
	m "github.com/onsi/gomega"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signature"
	"github.com/deckhouse/delivery-kit-sdk/pkg/signature/elf/inhouse"
	"github.com/deckhouse/delivery-kit-sdk/test/pkg/cert_utils"
)

var _ = g.Describe("legacy ELF interoperability", g.Label("elf-legacy", "e2e"), func() {
	g.BeforeEach(func() {
		m.Expect(os.Getenv("ELF_LEGACY_TOOL")).NotTo(m.BeEmpty(), "run task test:elf-legacy")
	})
	g.DescribeTable("Given an ELF encoding, then old and new hashes and verifiers interoperate",
		func(ctx g.SpecContext, class elf.Class, order binary.ByteOrder, machine elf.Machine) {
			path := writeELF(minimalELF(class, order, machine))
			sv := newSignerVerifier(ctx)
			m.Expect(inhouse.Sign(ctx, sv, path)).To(m.Succeed())
			legacyVerify(ctx, path)
			m.Expect(inhouse.Sign(ctx, sv, path)).To(m.Succeed())
			legacyVerify(ctx, path)
			for range 2 {
				bundle, err := signature.Sign(ctx, sv, string(legacyCommand(ctx, "hash", path)))
				m.Expect(err).NotTo(m.HaveOccurred())
				payload, err := json.Marshal(bundle)
				m.Expect(err).NotTo(m.HaveOccurred())
				payloadPath := filepath.Join(g.GinkgoT().TempDir(), "bundle.json")
				m.Expect(os.WriteFile(payloadPath, payload, 0o600)).To(m.Succeed())
				legacyCommand(ctx, "embed", path, payloadPath)
			}
			m.Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, path)).To(m.Succeed())
			m.Expect(inhouse.Sign(ctx, sv, path)).To(m.Succeed())
			legacyVerify(ctx, path)
		},
		g.Entry("ELF32 LE", elf.ELFCLASS32, binary.LittleEndian, elf.EM_386),
		g.Entry("ELF32 BE", elf.ELFCLASS32, binary.BigEndian, elf.EM_ARM),
		g.Entry("ELF64 LE", elf.ELFCLASS64, binary.LittleEndian, elf.EM_X86_64),
		g.Entry("ELF64 BE", elf.ELFCLASS64, binary.BigEndian, elf.EM_AARCH64),
	)
})

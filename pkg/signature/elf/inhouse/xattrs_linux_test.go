package inhouse_test

import (
	"bytes"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"syscall"

	g "github.com/onsi/ginkgo/v2"
	m "github.com/onsi/gomega"
	"golang.org/x/sys/unix"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signature/elf/inhouse"
	"github.com/deckhouse/delivery-kit-sdk/test/pkg/cert_utils"
)

var _ = g.Describe("Linux ELF metadata", func() {
	readAttribute := func(path, name string) []byte {
		buf := make([]byte, 65536)
		n, err := unix.Getxattr(path, name, buf)
		m.Expect(err).NotTo(m.HaveOccurred())
		return buf[:n]
	}
	acl, err := hex.DecodeString("0200000001000700ffffffff02000400e903000004000000ffffffff10000400ffffffff20000000ffffffff")
	if err != nil {
		panic(err)
	}
	capabilities, err := hex.DecodeString("0100000200040000000000000000000000000000")
	if err != nil {
		panic(err)
	}

	g.DescribeTable("Given an attributed ELF, then signing and re-signing preserve metadata", func(ctx g.SpecContext, name string, value []byte, privileged bool) {
		if privileged && os.Geteuid() != 0 {
			m.Expect(os.Getenv("DK_ELF_REQUIRE_ROOT")).NotTo(m.Equal("1"))
			g.Skip("setting file capabilities requires root")
		}
		path := writeELF(readFile(helloElfFile))
		m.Expect(unix.Setxattr(path, name, value, 0)).To(m.Succeed())
		before, err := os.Stat(path)
		m.Expect(err).NotTo(m.HaveOccurred())
		m.Expect(readAttribute(path, name)).To(m.Equal(value))
		for range 2 {
			m.Expect(inhouse.Sign(ctx, newSignerVerifier(ctx), path)).To(m.Succeed())
			m.Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, path)).To(m.Succeed())
			m.Expect(readAttribute(path, name)).To(m.Equal(value))
			after, err := os.Stat(path)
			m.Expect(err).NotTo(m.HaveOccurred())
			m.Expect(after.Mode()).To(m.Equal(before.Mode()))
		}
	},
		g.Entry("binary user attribute", "user.delivery-kit", []byte{0, 1, 255, 0, 5}, false),
		g.Entry("empty user attribute", "user.empty", []byte{}, false),
		g.Entry("POSIX access ACL", "system.posix_acl_access", acl, false),
		g.Entry("file capabilities", "security.capability", capabilities, true),
		g.Entry("trusted namespace", "trusted.delivery-kit", []byte("trusted metadata"), true),
		g.Entry("SELinux label value", "security.selinux", []byte("unconfined_u:object_r:user_tmp_t:s0\x00"), true),
	)

	g.It("Given combined ACL capabilities and setuid metadata, then re-signing preserves all of them", func(ctx g.SpecContext) {
		if os.Geteuid() != 0 {
			m.Expect(os.Getenv("DK_ELF_REQUIRE_ROOT")).NotTo(m.Equal("1"))
			g.Skip("preparing privileged attributes requires root")
		}
		path := writeELF(readFile(helloElfFile))
		attrs := map[string][]byte{"system.posix_acl_access": acl, "security.capability": capabilities, "user.combined": []byte("metadata")}
		m.Expect(unix.Setxattr(path, "system.posix_acl_access", acl, 0)).To(m.Succeed())
		mode := os.ModeSetuid | os.ModeSetgid | os.FileMode(0o740)
		m.Expect(os.Chmod(path, mode)).To(m.Succeed())
		for name, value := range attrs {
			m.Expect(unix.Setxattr(path, name, value, 0)).To(m.Succeed())
		}
		for range 2 {
			m.Expect(inhouse.Sign(ctx, newSignerVerifier(ctx), path)).To(m.Succeed())
			for name, value := range attrs {
				m.Expect(readAttribute(path, name)).To(m.Equal(value))
			}
			info, err := os.Stat(path)
			m.Expect(err).NotTo(m.HaveOccurred())
			m.Expect(info.Mode()).To(m.Equal(mode))
			m.Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, path)).To(m.Succeed())
		}
	})

	g.It("Given read-only ACL and user attributes, then their owner can sign without write permission on the source", func(ctx g.SpecContext) {
		readOnlyACL := bytes.Clone(acl)
		readOnlyACL[6] = 5
		if path := os.Getenv("DK_ELF_READONLY_INPUT"); path != "" {
			m.Expect(os.Geteuid()).To(m.Equal(1000))
			m.Expect(inhouse.Sign(ctx, newSignerVerifier(ctx), path)).To(m.Succeed())
			m.Expect(readAttribute(path, "user.readonly")).To(m.Equal([]byte("read-only metadata")))
			m.Expect(readAttribute(path, "system.posix_acl_access")).To(m.Equal(readOnlyACL))
			info, err := os.Stat(path)
			m.Expect(err).NotTo(m.HaveOccurred())
			m.Expect(info.Mode()).To(m.Equal(os.FileMode(0o540)))
			m.Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, path)).To(m.Succeed())
			return
		}
		if os.Geteuid() != 0 {
			m.Expect(os.Getenv("DK_ELF_REQUIRE_ROOT")).NotTo(m.Equal("1"))
			g.Skip("preparing an unprivileged subprocess requires root")
		}
		dir := g.GinkgoT().TempDir()
		m.Expect(os.Chmod(dir, 0o777)).To(m.Succeed())
		path := filepath.Join(dir, "input.elf")
		m.Expect(os.WriteFile(path, readFile(helloElfFile), 0o700)).To(m.Succeed())
		m.Expect(os.Chown(path, 1000, 1000)).To(m.Succeed())
		m.Expect(unix.Setxattr(path, "user.readonly", []byte("read-only metadata"), 0)).To(m.Succeed())
		m.Expect(unix.Setxattr(path, "system.posix_acl_access", readOnlyACL, 0)).To(m.Succeed())
		executable, err := os.Executable()
		m.Expect(err).NotTo(m.HaveOccurred())
		child := filepath.Join(dir, "readonly.test")
		m.Expect(os.WriteFile(child, readFile(executable), 0o755)).To(m.Succeed())
		for _, inherited := range []bool{false, true} {
			if inherited {
				m.Expect(unix.Setxattr(dir, "system.posix_acl_default", readOnlyACL, 0)).To(m.Succeed())
			}
			cmd := exec.CommandContext(ctx, child, "-ginkgo.focus="+regexp.QuoteMeta(g.CurrentSpecReport().FullText()), "-ginkgo.fail-on-empty")
			cmd.Env = append(os.Environ(), "DK_ELF_READONLY_INPUT="+path)
			cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1000, Gid: 1000, Groups: []uint32{1000}}}
			output, err := cmd.CombinedOutput()
			m.Expect(err).NotTo(m.HaveOccurred(), string(output))
		}
	})

	g.DescribeTable("Given an integrity-protected ELF, then signing refuses stale integrity metadata", func(ctx g.SpecContext, name string) {
		if os.Geteuid() != 0 {
			m.Expect(os.Getenv("DK_ELF_REQUIRE_ROOT")).NotTo(m.Equal("1"))
			g.Skip("preparing security attributes requires root")
		}
		path := writeELF(readFile(helloElfFile))
		value := []byte("integrity metadata")
		m.Expect(unix.Setxattr(path, name, value, 0)).To(m.Succeed())
		original := readFile(path)
		m.Expect(inhouse.Sign(ctx, newSignerVerifier(ctx), path)).To(m.MatchError(m.ContainSubstring("requires integrity re-signing")))
		m.Expect(readFile(path)).To(m.Equal(original))
		m.Expect(readAttribute(path, name)).To(m.Equal(value))
		leftovers, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".delivery-kit-sign-*"))
		m.Expect(err).NotTo(m.HaveOccurred())
		m.Expect(leftovers).To(m.BeEmpty())
	},
		g.Entry("IMA", "security.ima"),
		g.Entry("EVM", "security.evm"),
	)

	g.It("Given a directory default ACL absent from the source, then signing does not inherit extra access", func(ctx g.SpecContext) {
		dir := g.GinkgoT().TempDir()
		m.Expect(unix.Setxattr(dir, "system.posix_acl_default", acl, 0)).To(m.Succeed())
		path := filepath.Join(dir, "input.elf")
		m.Expect(os.WriteFile(path, readFile(helloElfFile), 0o740)).To(m.Succeed())
		m.Expect(readAttribute(path, "system.posix_acl_access")).NotTo(m.BeEmpty())
		m.Expect(unix.Removexattr(path, "system.posix_acl_access")).To(m.Succeed())
		m.Expect(inhouse.Sign(ctx, newSignerVerifier(ctx), path)).To(m.Succeed())
		_, err := unix.Getxattr(path, "system.posix_acl_access", make([]byte, 65536))
		m.Expect(err).To(m.Equal(unix.ENODATA))
		info, err := os.Stat(path)
		m.Expect(err).NotTo(m.HaveOccurred())
		m.Expect(info.Mode().Perm()).To(m.Equal(os.FileMode(0o740)))
	})

	g.It("Given an xattr the signer cannot restore, then signing preserves the original file", func(ctx g.SpecContext) {
		if path := os.Getenv("DK_ELF_XATTR_INPUT"); path != "" {
			m.Expect(os.Geteuid()).To(m.Equal(1000))
			original := readFile(path)
			before, err := os.Stat(path)
			m.Expect(err).NotTo(m.HaveOccurred())
			err = inhouse.Sign(ctx, newSignerVerifier(ctx), path)
			m.Expect(err).To(m.MatchError(m.ContainSubstring("preserve ELF extended attributes:")))
			m.Expect(readFile(path)).To(m.Equal(original))
			m.Expect(readAttribute(path, "security.capability")).To(m.Equal(capabilities))
			after, err := os.Stat(path)
			m.Expect(err).NotTo(m.HaveOccurred())
			m.Expect(os.SameFile(before, after)).To(m.BeTrue())
			leftovers, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".delivery-kit-sign-*"))
			m.Expect(err).NotTo(m.HaveOccurred())
			m.Expect(leftovers).To(m.BeEmpty())
			return
		}
		if os.Geteuid() != 0 {
			m.Expect(os.Getenv("DK_ELF_REQUIRE_ROOT")).NotTo(m.Equal("1"))
			g.Skip("preparing privileged attributes requires root")
		}
		dir := g.GinkgoT().TempDir()
		m.Expect(os.Chmod(dir, 0o777)).To(m.Succeed())
		path := filepath.Join(dir, "input.elf")
		m.Expect(os.WriteFile(path, readFile(helloElfFile), 0o700)).To(m.Succeed())
		m.Expect(os.Chown(path, 1000, 1000)).To(m.Succeed())
		m.Expect(unix.Setxattr(path, "security.capability", capabilities, 0)).To(m.Succeed())
		executable, err := os.Executable()
		m.Expect(err).NotTo(m.HaveOccurred())
		child := filepath.Join(dir, "metadata.test")
		m.Expect(os.WriteFile(child, readFile(executable), 0o755)).To(m.Succeed())
		cmd := exec.CommandContext(ctx, child, "-ginkgo.focus="+regexp.QuoteMeta(g.CurrentSpecReport().FullText()), "-ginkgo.fail-on-empty")
		cmd.Env = append(os.Environ(), "DK_ELF_XATTR_INPUT="+path)
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1000, Gid: 1000, Groups: []uint32{1000}}}
		output, err := cmd.CombinedOutput()
		m.Expect(err).NotTo(m.HaveOccurred(), string(output))
	})
})

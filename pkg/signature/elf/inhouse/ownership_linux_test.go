package inhouse_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	g "github.com/onsi/ginkgo/v2"
	m "github.com/onsi/gomega"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signature/elf/inhouse"
	"github.com/deckhouse/delivery-kit-sdk/test/pkg/cert_utils"
)

var _ = g.It("Given a foreign-owned setuid ELF, then signing preserves its owner, group and privilege bits", func(ctx g.SpecContext) {
	if os.Geteuid() != 0 {
		m.Expect(os.Getenv("DK_ELF_REQUIRE_ROOT")).NotTo(m.Equal("1"), "privileged CI must run as root")
		g.Skip("changing file ownership requires root")
	}
	path := writeELF(readFile(helloElfFile))
	m.Expect(os.Chown(path, 1000, 1000)).To(m.Succeed())
	mode := os.ModeSetuid | os.ModeSetgid | os.FileMode(0o751)
	m.Expect(os.Chmod(path, mode)).To(m.Succeed())
	m.Expect(inhouse.Sign(ctx, newSignerVerifier(ctx), path)).To(m.Succeed())
	info, err := os.Stat(path)
	m.Expect(err).NotTo(m.HaveOccurred())
	stat, ok := info.Sys().(*syscall.Stat_t)
	m.Expect(ok).To(m.BeTrue())
	m.Expect(stat.Uid).To(m.Equal(uint32(1000)))
	m.Expect(stat.Gid).To(m.Equal(uint32(1000)))
	m.Expect(info.Mode()).To(m.Equal(mode))
})

var _ = g.It("Given a FIFO with no writer, then both entry points reject it without blocking", func(ctx g.SpecContext) {
	path := filepath.Join(g.GinkgoT().TempDir(), "fifo")
	m.Expect(syscall.Mkfifo(path, 0o600)).To(m.Succeed())
	sv := newSignerVerifier(ctx)
	for _, operation := range []func() error{
		func() error { return inhouse.Sign(ctx, sv, path) },
		func() error { return inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, path) },
	} {
		done := make(chan error, 1)
		go func() { done <- operation() }()
		var result error
		blocked := false
		select {
		case result = <-done:
		case <-time.After(2 * time.Second):
			blocked = true
			unblock, err := os.OpenFile(path, os.O_RDWR, 0)
			m.Expect(err).NotTo(m.HaveOccurred())
			result = <-done
			m.Expect(unblock.Close()).To(m.Succeed())
		}
		m.Expect(blocked).To(m.BeFalse(), "opening a FIFO must not wait for a writer")
		m.Expect(result).To(m.MatchError("ELF requires a regular file"))
	}
})

var _ = g.It("Given ordinary ELF ownership unavailable to the signer, then signing fails without replacing the source", func(ctx g.SpecContext) {
	if path := os.Getenv("DK_ELF_UNPRIVILEGED_INPUT"); path != "" {
		m.Expect(os.Geteuid()).To(m.Equal(1000))
		original := readFile(path)
		before, err := os.Stat(path)
		m.Expect(err).NotTo(m.HaveOccurred())
		err = inhouse.Sign(ctx, newSignerVerifier(ctx), path)
		m.Expect(err).To(m.MatchError(m.ContainSubstring("preserve ELF ownership:")))
		m.Expect(readFile(path)).To(m.Equal(original))
		after, err := os.Stat(path)
		m.Expect(err).NotTo(m.HaveOccurred())
		m.Expect(os.SameFile(before, after)).To(m.BeTrue())
		m.Expect(after.Mode()).To(m.Equal(before.Mode()))
		m.Expect(after.Sys().(*syscall.Stat_t).Uid).To(m.Equal(before.Sys().(*syscall.Stat_t).Uid))
		m.Expect(after.Sys().(*syscall.Stat_t).Gid).To(m.Equal(before.Sys().(*syscall.Stat_t).Gid))
		leftovers, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".delivery-kit-sign-*"))
		m.Expect(err).NotTo(m.HaveOccurred())
		m.Expect(leftovers).To(m.BeEmpty())
		return
	}
	if os.Geteuid() != 0 {
		m.Expect(os.Getenv("DK_ELF_REQUIRE_ROOT")).NotTo(m.Equal("1"), "privileged CI must run as root")
		g.Skip("preparing foreign ownership requires root")
	}
	dir := g.GinkgoT().TempDir()
	m.Expect(os.Chmod(dir, 0o777)).To(m.Succeed())
	executable, err := os.Executable()
	m.Expect(err).NotTo(m.HaveOccurred())
	child := filepath.Join(dir, "ownership.test")
	m.Expect(os.WriteFile(child, readFile(executable), 0o755)).To(m.Succeed())
	for _, uid := range []int{0, 1000} {
		path := filepath.Join(dir, "input.elf")
		m.Expect(os.WriteFile(path, readFile(helloElfFile), 0o666)).To(m.Succeed())
		m.Expect(os.Chown(path, uid, 0)).To(m.Succeed())
		m.Expect(os.Chmod(path, 0o666)).To(m.Succeed())
		cmd := exec.CommandContext(ctx, child, "-ginkgo.focus="+regexp.QuoteMeta(g.CurrentSpecReport().FullText()), "-ginkgo.fail-on-empty")
		cmd.Env = append(os.Environ(), "DK_ELF_UNPRIVILEGED_INPUT="+path)
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1000, Gid: 1000, Groups: []uint32{1000}}}
		output, err := cmd.CombinedOutput()
		m.Expect(err).NotTo(m.HaveOccurred(), string(output))
	}
})

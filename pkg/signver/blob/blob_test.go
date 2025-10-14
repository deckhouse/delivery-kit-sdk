package blob_test

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signver/blob"
)

var _ = Describe("LoadURLOrBase64OrFile", func() {
	DescribeTable("with base64 input",
		func(expected []byte) {
			input := base64.StdEncoding.EncodeToString(expected)
			actual, err := blob.LoadURLOrBase64OrFile(input)
			Expect(err).To(Succeed())
			Expect(actual).To(Equal(expected))
		},
		Entry("valid base64", []byte("test")),
	)

	DescribeTable("with file input",
		func(useAbsolutePath bool, filePath string) {
			if runtime.GOOS == "windows" {
				Skip("Skipping on Windows due to https://github.com/golang/go/issues/51442")
			}

			tmpDir := GinkgoT().TempDir()

			expected := []byte("test")
			err := os.WriteFile(filepath.Join(tmpDir, filePath), expected, 0o400)
			Expect(err).To(Succeed())

			if useAbsolutePath {
				filePath = filepath.Join(tmpDir, filePath)
			} else {
				Expect(os.Chdir(tmpDir)).To(Succeed())
			}

			actual, err := blob.LoadURLOrBase64OrFile(filePath)
			Expect(err).To(Succeed())
			Expect(actual).To(Equal(expected))
		},
		Entry("absolute path", true, "filename.txt"),
		Entry("relative path", false, "filename.txt"),
	)

	DescribeTable("with URL input",
		func(url string, expected []byte, expectErr types.GomegaMatcher) {
			server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
				rw.Write(expected)
			}))
			defer server.Close()

			if url == "http://with-server-url" {
				url = server.URL
			}

			if strings.HasPrefix(url, "env://") && expected != nil {
				GinkgoT().Setenv(strings.TrimPrefix(url, "env://"), string(expected))
			}

			actual, err := blob.LoadURLOrBase64OrFile(url)
			Expect(err).To(expectErr)
			Expect(actual).To(Equal(expected))
		},
		Entry("real server url", "http://with-server-url", []byte("test"), Succeed()),
		Entry("environment variable set", "env://MY_ENV_VAR", []byte("test"), Succeed()),
		Entry("environment variable empty", "env://MY_ENV_VAR", []byte(""), Succeed()),
		Entry("environment variable is not set", "env://MY_ENV_VAR", nil, HaveOccurred()),
		Entry("invalid scheme", "invalid://url", nil, HaveOccurred()),
	)
})

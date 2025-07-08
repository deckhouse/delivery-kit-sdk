package signature_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signature"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("bundle", func() {
	Describe("Base64Bytes", func() {
		DescribeTable("should marshal/unmarshal to/from JSON using base64 encoding/decoding",
			func(decoded string) {
				bb := signature.Base64Bytes(decoded)
				marshaled, err := json.Marshal(bb)
				Expect(err).To(Succeed())
				Expect(string(marshaled)).To(Equal(fmt.Sprintf("%q", base64.StdEncoding.EncodeToString(bb))))

				bb2 := signature.Base64Bytes{}
				err = json.Unmarshal(marshaled, &bb2)
				Expect(err).To(Succeed())
				Expect(string(bb2)).To(Equal(decoded))
			},
			Entry(
				"should work with simple value",
				"test",
			),
		)
	})
	Describe("Empty Bundle", func() {
		DescribeTable("map conversion",
			func(expected map[string]string) {
				bundle := signature.NewEmptyBundle()
				actual, err := bundle.ToMap()
				Expect(err).To(Succeed())
				Expect(actual).To(Equal(expected))
			},
			Entry(
				"should have three keys and all empty values",
				map[string]string{
					"io.deckhouse.delivery-kit.signature": "",
					"io.deckhouse.delivery-kit.cert":      "",
					"io.deckhouse.delivery-kit.chain":     "",
				},
			),
		)
	})
	DescribeTable("NewBundleFromMap",
		func(m map[string]string, expectedBundle signature.Bundle, expectedErr error) {
			b, err := signature.NewBundleFromMap(m)
			Expect(errors.Is(err, expectedErr)).To(BeTrue())
			Expect(b).To(Equal(expectedBundle))
		},
		Entry(
			"should fail with 'no signature annotation' if no specified anno",
			map[string]string{},
			signature.Bundle{},
			signature.ErrNoSignature,
		),
		Entry(
			"should fail with 'no cert annotation' if no specified anno",
			map[string]string{
				"io.deckhouse.delivery-kit.signature": "",
			},
			signature.Bundle{},
			signature.ErrNoCert,
		),
		Entry(
			"should return bundle otherwise",
			map[string]string{
				"io.deckhouse.delivery-kit.signature": base64.StdEncoding.EncodeToString([]byte("sig")),
				"io.deckhouse.delivery-kit.cert":      base64.StdEncoding.EncodeToString([]byte("cert")),
				"io.deckhouse.delivery-kit.chain":     base64.StdEncoding.EncodeToString([]byte("chain")),
			},
			signature.Bundle{
				Signature: []byte("sig"),
				Cert:      []byte("cert"),
				Chain:     []byte("chain"),
			},
			nil,
		),
	)
})

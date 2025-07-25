package blob

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type UnrecognizedSchemeError struct {
	Scheme string
}

func (e *UnrecognizedSchemeError) Error() string {
	return fmt.Sprintf("loading URL: unrecognized scheme: %s", e.Scheme)
}

func LoadURLOrBase64OrFile(fileRef string) ([]byte, error) {
	var raw []byte
	parts := strings.SplitAfterN(fileRef, "://", 2)
	if len(parts) == 2 {
		scheme := parts[0]
		switch scheme {
		case "http://":
			fallthrough
		case "https://":
			// #nosec G107
			resp, err := http.Get(fileRef)
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()
			raw, err = io.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}
		case "env://":
			envVar := parts[1]
			// Most of Cosign should use `env.LookupEnv` (see #2236) to restrict us to known environment variables
			// (usually `$COSIGN_*`). However, in this case, `envVar` is user-provided and not one of the allow-listed
			// env vars.
			value, found := os.LookupEnv(envVar) //nolint:forbidigo
			if !found {
				return nil, fmt.Errorf("loading URL: env var $%s not found", envVar)
			}
			raw = []byte(value)
		default:
			return nil, &UnrecognizedSchemeError{Scheme: scheme}
		}
	} else {
		return LoadBase64OrFile(fileRef)
	}
	return raw, nil
}

func LoadBase64OrFile(fileRef string) ([]byte, error) {
	var raw []byte
	var err error
	if raw, err = base64.StdEncoding.DecodeString(fileRef); err == nil {
		return raw, nil
	} else if raw, err = os.ReadFile(filepath.Clean(fileRef)); err != nil {
		return nil, err
	}
	return raw, err
}

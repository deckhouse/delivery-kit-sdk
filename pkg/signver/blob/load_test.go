//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package blob

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"runtime"
	"testing"
)

func TestLoadBase64(t *testing.T) {
	data := []byte("test")

	decoded := base64.StdEncoding.EncodeToString(data)

	actual, err := LoadURLOrBase64OrFile(decoded)
	if err != nil {
		t.Errorf("Reading base64 %q: %v", decoded, err)
	} else if !bytes.Equal(actual, data) {
		t.Errorf("LoadURLOrBase64OrFile(base64) = '%s'; want '%s'", actual, data)
	}
}

func TestLoadFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping on Windows due to https://github.com/golang/go/issues/51442")
	}
	temp := t.TempDir()
	fname := "filename.txt"
	path := path.Join(temp, fname)
	data := []byte("test")
	defer os.Remove(path)
	os.WriteFile(path, data, 0o400)

	// absolute path
	actual, err := LoadURLOrBase64OrFile(path)
	if err != nil {
		t.Errorf("Reading from absolute path %s failed: %v", path, err)
	} else if !bytes.Equal(actual, data) {
		t.Errorf("LoadURLOrBase64OrFile(absolute path) = '%s'; want '%s'", actual, data)
	}

	if err = os.Chdir(temp); err != nil {
		t.Fatalf("Chdir('%s'): %v", temp, err)
	}
	actual, err = LoadURLOrBase64OrFile(fname)
	if err != nil {
		t.Errorf("Reading from relative path %s failed: %v", fname, err)
	} else if !bytes.Equal(actual, data) {
		t.Errorf("LoadURLOrBase64OrFile(relative path) = '%s'; want '%s'", actual, data)
	}
}

func TestLoadURL(t *testing.T) {
	data := []byte("test")

	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Write(data)
	}))
	defer server.Close()

	actual, err := LoadURLOrBase64OrFile(server.URL)
	if err != nil {
		t.Errorf("Reading from HTTP failed: %v", err)
	} else if !bytes.Equal(actual, data) {
		t.Errorf("LoadURLOrBase64OrFile(HTTP) = '%s'; want '%s'", actual, data)
	}

	os.Setenv("MY_ENV_VAR", string(data))
	actual, err = LoadURLOrBase64OrFile("env://MY_ENV_VAR")
	if err != nil {
		t.Errorf("Reading from environment failed: %v", err)
	} else if !bytes.Equal(actual, data) {
		t.Errorf("LoadURLOrBase64OrFile(env) = '%s'; want '%s'", actual, data)
	}

	os.Setenv("MY_ENV_VAR", "")
	actual, err = LoadURLOrBase64OrFile("env://MY_ENV_VAR")
	if err != nil {
		t.Errorf("Reading from environment failed: %v", err)
	} else if !bytes.Equal(actual, make([]byte, 0)) {
		t.Errorf("LoadURLOrBase64OrFile(env) = '%s'; should be empty", actual)
	}

	os.Unsetenv("MY_ENV_VAR")
	_, err = LoadURLOrBase64OrFile("env://MY_ENV_VAR")
	if err == nil {
		t.Error("LoadURLOrBase64OrFile(): expected error for unset env var")
	}

	_, err = LoadURLOrBase64OrFile("invalid://url")
	if err == nil {
		t.Error("LoadURLOrBase64OrFile(): expected error for invalid scheme")
	}
}

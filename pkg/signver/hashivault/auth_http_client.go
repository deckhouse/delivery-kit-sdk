package hashivault

import (
	"net/http"
	"time"
)

var authHTTPClient = &http.Client{
	Timeout: 30 * time.Second,

	// TODO: add retry logic
}

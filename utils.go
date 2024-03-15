package sessions

import (
	"net/http"
	"time"
)

// Helpers --------------------------------------------------------------------

// Save saves all sessions used during the current request.
func Save(r *http.Request, w http.ResponseWriter) error {
	return GetRegistry(r).Save(w)
}

// NewCookie returns a http.Cookie with the options set. It also sets
// the Expires field calculated based on the MaxAge value, for Internet
// Explorer compatibility.
func NewCookie(name, value string, options *Options) *http.Cookie {
	cookie := newCookieFromOptions(name, value, options)
	if options.Expires.IsZero() {
		if options.MaxAge > 0 {
			d := time.Duration(options.MaxAge) * time.Second
			cookie.Expires = time.Now().Add(d)
		} else if options.MaxAge < 0 {
			// Set it to the past to expire now.
			cookie.Expires = time.Unix(1, 0)
		}
	}
	return cookie
}


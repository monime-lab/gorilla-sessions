package sessions

import (
	"net/http"
)

// newCookieFromOptions returns a http.Cookie with the options set.
func newCookieFromOptions(name, value string, options *Options) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     options.Path,
		Domain:   options.Domain,
		Expires:  options.Expires,
		MaxAge:   options.MaxAge,
		Secure:   options.Secure,
		HttpOnly: options.HttpOnly,
		SameSite: options.SameSite,
	}
}

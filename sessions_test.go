// Copyright 2012 The Gorilla Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sessions

import (
	"bytes"
	"encoding/gob"
	"net/http"
	"net/http/httptest"
	"testing"
)

// NewRecorder returns an initialized ResponseRecorder.
func NewRecorder() *httptest.ResponseRecorder {
	return &httptest.ResponseRecorder{
		HeaderMap: make(http.Header),
		Body:      new(bytes.Buffer),
	}
}

// ----------------------------------------------------------------------------

type FlashMessage struct {
	Type    int
	Message string
}

func TestFlashes(t *testing.T) {
	var req *http.Request
	var rsp *httptest.ResponseRecorder
	var hdr http.Header
	var err error
	var ok bool
	var cookies []string
	var session *Session

	store := NewCookieStore([]byte("secret-key"))

	// Round 1 ----------------------------------------------------------------

	req, _ = http.NewRequest("GET", "http://localhost:8080/", nil)
	rsp = NewRecorder()
	// Get a session.
	if session, err = store.Get(req, "session-key"); err != nil {
		t.Fatalf("Error getting session: %v", err)
	}
	// Save.
	if err = Save(req, rsp); err != nil {
		t.Fatalf("Error saving session: %v", err)
	}
	hdr = rsp.Header()
	cookies, ok = hdr["Set-Cookie"]
	if !ok || len(cookies) != 1 {
		t.Fatal("No cookies. Header:", hdr)
	}

	if _, err = store.Get(req, "session:key"); err.Error() != "sessions: invalid character in cookie name: session:key" {
		t.Fatalf("Expected error due to invalid cookie name")
	}

	// Round 2 ----------------------------------------------------------------

	req, _ = http.NewRequest("GET", "http://localhost:8080/", nil)
	req.Header.Add("Cookie", cookies[0])
	// Get a session.
	if session, err = store.Get(req, "session-key"); err != nil {
		t.Fatalf("Error getting session: %v", err)
	}
	// Round 3 ----------------------------------------------------------------
	// Custom type

	req, _ = http.NewRequest("GET", "http://localhost:8080/", nil)
	rsp = NewRecorder()
	// Get a session.
	if session, err = store.Get(req, "session-key"); err != nil {
		t.Fatalf("Error getting session: %v", err)
	}
	// Save.
	if err = Save(req, rsp); err != nil {
		t.Fatalf("Error saving session: %v", err)
	}
	hdr = rsp.Header()
	cookies, ok = hdr["Set-Cookie"]
	if !ok || len(cookies) != 1 {
		t.Fatal("No cookies. Header:", hdr)
	}

	// Round 4 ----------------------------------------------------------------
	// Custom type

	req, _ = http.NewRequest("GET", "http://localhost:8080/", nil)
	req.Header.Add("Cookie", cookies[0])
	// Get a session.
	if session, err = store.Get(req, "session-key"); err != nil {
		t.Fatalf("Error getting session: %v", err)
	}
	// Round 5 ----------------------------------------------------------------
	// Check if a request shallow copy resets the request context data store.

	req, _ = http.NewRequest("GET", "http://localhost:8080/", nil)

	// Get a session.
	if session, err = store.Get(req, "session-key"); err != nil {
		t.Fatalf("Error getting session: %v", err)
	}

	// Put a test value into the session data store.
	session.Values["test"] = "test-value"

	// Create a shallow copy of the request.
	req = req.WithContext(req.Context())

	// Get the session again.
	if session, err = store.Get(req, "session-key"); err != nil {
		t.Fatalf("Error getting session: %v", err)
	}

	// Check if the previous inserted value still exists.
	if session.Values["test"] == nil {
		t.Fatalf("Session test value is lost in the request context!")
	}

	// Check if the previous inserted value has the same value.
	if session.Values["test"] != "test-value" {
		t.Fatalf("Session test value is changed in the request context!")
	}
}

func TestCookieStoreMapPanic(t *testing.T) {
	defer func() {
		err := recover()
		if err != nil {
			t.Fatal(err)
		}
	}()

	store := NewCookieStore([]byte("aaa0defe5d2839cbc46fc4f080cd7adc"))
	req, err := http.NewRequest("GET", "http://www.example.com", nil)
	if err != nil {
		t.Fatal("failed to create request", err)
	}
	w := httptest.NewRecorder()

	session := NewSession(store, "hello")

	session.Values["data"] = "hello-world"

	err = session.Save(req, w)
	if err != nil {
		t.Fatal("failed to save session", err)
	}
}

func init() {
	gob.Register(FlashMessage{})
}

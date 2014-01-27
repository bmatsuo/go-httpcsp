// Copyright 2014, Bryan Matsuo. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// httpcsp_test.go [created: Sun, 26 Jan 2014]

package httpcsp

import (
	y "github.com/bmatsuo/yup"
	ytxt "github.com/bmatsuo/yup/yuptext"
	yt "github.com/bmatsuo/yup/yuptype"

	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type mockViolationHandler struct {
	called bool
	v      *Violation
}

func (mock *mockViolationHandler) Handle(resp http.ResponseWriter, v *Violation) {
	mock.called = true
	mock.v = v
}

func TestViolationHandlerMethodNotAllowed(t *testing.T) {
	for _, method := range []string{"GET", "PUT", "DELETE"} {
		mock := new(mockViolationHandler)
		vh := ViolationHandler(mock.Handle)
		rec := httptest.NewRecorder()
		req, err := http.NewRequest(method, "/", nil)

		yt.Nil(t, err)
		vh.ServeHTTP(rec, req)

		yt.Equal(t, http.StatusMethodNotAllowed, rec.Code,
			method+" not rejected")
		yt.Equal(t, "POST", rec.Header().Get("Allow"),
			method+": only POST should be allowed")
		y.Assert(t, !mock.called, "handler called erroneously")
	}
}

func TestViolationHandlerUnsupportedContentType(t *testing.T) {
	mock := new(mockViolationHandler)
	vh := ViolationHandler(mock.Handle)
	rec := httptest.NewRecorder()
	req, err := http.NewRequest("POST", "/", strings.NewReader(""))
	yt.Nil(t, err)
	vh.ServeHTTP(rec, req)
	yt.Equal(t, http.StatusUnsupportedMediaType, rec.Code,
		"text/plain content accepted")
	ytxt.ContainsString(t, rec.Body.String(), "application/json",
		"doesn't tell the client to use an application/json content type")
}

func TestViolationHandlerInvalidRequest(t *testing.T) {
	mock := new(mockViolationHandler)
	vh := ViolationHandler(mock.Handle)
	rec := httptest.NewRecorder()
	req, err := http.NewRequest("POST", "/", strings.NewReader(`[]`))
	yt.Nil(t, err)
	req.Header.Set("Content-Type", "application/json")
	vh.ServeHTTP(rec, req)
	yt.Equal(t, http.StatusBadRequest, rec.Code, "json array accepted")
	// TODO test entity

	mock = new(mockViolationHandler)
	vh = ViolationHandler(mock.Handle)
	rec = httptest.NewRecorder()
	req, err = http.NewRequest("POST", "/", strings.NewReader(`[]`))
	yt.Nil(t, err)
	req.Header.Set("Content-Type", "application/csp-report")
	vh.ServeHTTP(rec, req)
	yt.Equal(t, http.StatusBadRequest, rec.Code, "json array accepted")
	// TODO test entity
}

func TestViolationHandlerSuccess(t *testing.T) {
	mock := new(mockViolationHandler)
	vh := ViolationHandler(mock.Handle)
	rec := httptest.NewRecorder()
	req, err := http.NewRequest("POST", "/", strings.NewReader(`{}`))
	yt.Nil(t, err)
	req.Header.Set("Content-Type", "application/json")
	vh.ServeHTTP(rec, req)
	yt.Equal(t, http.StatusOK, rec.Code, "empty report rejected")
	y.Assert(t, mock.called, "the callback was invoked")
}

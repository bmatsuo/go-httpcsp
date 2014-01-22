// Copyright 2013, Bryan Matsuo. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// netcsp.go [created: Sun, 28 Jul 2013]

/*
Utilities for applying web content security policies (W3C CSP 1.0).

Disclaimer

This package is under development and the API has not yet stabilized.

Building policies

The Policy type allows web applications to incrementally build/extend security
policies. Policies are compiled and then applied to response headers.

Violation reports

Policy violation reports can be handled with http.Handlers constructed with
the ViolationHandler() wrapper function.
*/
package httpcsp

import (
	"encoding/json"
	"net/http"
	"strings"
)

const (
	// The empty directive value. This has the effect of negating previosly
	// declared values for a directive in a policy. The value is only valid
	// for src directives. But Go-httpcsp allows it on other directives.
	NONE = "'none'"

	// Keyword sources applicable to src directives.
	SELF          = "'self'"
	UNSAFE_INLINE = "'unsafe-inline'"
	UNSAFE_EVAL   = "'unsafe-eval'"

	// Common scheme sources applicable to src directives.
	HTTPS = "https:"
)

// A description of a security policy violation.
type CSPReport struct {
	DocumentURI       string `json:"document-uri"`
	Referrer          string `json:"referrer"`
	BlockedURI        string `json:"blocked-uri"`
	ViolatedDirective string `json:"violated-directive"`
	OriginalPolicy    string `json:"original-policy"`
}

// A policy violation reported by a browser.
type Violation struct {
	CSP *CSPReport `json:"csp-report"`
}

// Create a handler for security policy violations. Used in conjunction with
// Policy.ReportURI.
func ViolationHandler(f func(http.ResponseWriter, *Violation)) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		if req.Method != "POST" {
			resp.Header().Set("Allow", "POST")
			http.Error(resp, "", http.StatusMethodNotAllowed)
			return
		}

		defer req.Body.Close()

		mime := strings.SplitN(req.Header.Get("Content-Type"), ";", 2)[0]
		if mime != "application/json" && mime != "application/csp-report" {
			http.Error(resp, "", http.StatusUnsupportedMediaType)
			return
		}

		v := new(Violation)
		dec := json.NewDecoder(req.Body)
		err := dec.Decode(v)
		if err != nil {
			http.Error(resp, "", http.StatusBadRequest)
			return
		}

		if f != nil {
			f(resp, v)
		}
	})
}

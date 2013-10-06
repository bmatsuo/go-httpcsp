// Copyright 2013, Bryan Matsuo. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// netcsp.go [created: Sun, 28 Jul 2013]

/*
Web server utilities for implementing Content Security Policy (CSP) 1.0.
Go-httpcsp provides a type, CSP, which describes a security policy and can
be applied to http.ResponseWriter types. It also provides a simple
wrapper function, ViolationHandler, for creating http.Handlers for dealing
with reports of attempted policy violation.


For more information see Content Security Policy 1.0 (http://www.w3.org/TR/CSP).
*/
package httpcsp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const (
	// allowed keyword-sources
	SELF          = "'self'"
	UNSAFE_INLINE = "'unsafe-inline'"
	UNSAFE_EVAL   = "'unsafe-eval'"

	// common scheme-sources
	HTTPS         = "https:"
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
// CSP.ReportURI.
func ViolationHandler(f func(*Violation, error)) http.Handler {
	if f == nil {
		f = func(*Violation, error) {}
	}
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		v := new(Violation)
		dec := json.NewDecoder(req.Body)
		defer req.Body.Close()
		err := dec.Decode(v)
		f(v, err)
	})
}

type directive interface {
	Name() string
	EncodeDirective() string
}

type wspList struct {
	name string
	srcs []string
}

func (list wspList) Name() string {
	return list.name
}

func (list wspList) EncodeDirective() string {
	return fmt.Sprintf("%s %s", list.name, strings.Join(list.srcs, " "))
}

func defaultSrc(src ...string) directive { // 4.1
	return wspList{"default-src", src}
}
func scriptSrc(src ...string) directive { // 4.2
	return wspList{"script-src", src}
}
func objectSrc(src ...string) directive { // 4.3
	return wspList{"object-src", src}
}
func styleSrc(src ...string) directive { // 4.4
	return wspList{"style-src", src}
}
func imgSrc(src ...string) directive { // 4.5
	return wspList{"img-src", src}
}
func mediaSrc(src ...string) directive { // 4.6
	return wspList{"media-src", src}
}
func frameSrc(src ...string) directive { // 4.7
	return wspList{"frame-src", src}
}
func fontSrc(src ...string) directive { // 4.8
	return wspList{"font-src", src}
}
func connectSrc(src ...string) directive { // 4.9
	return wspList{"connect-src", src}
}
func reportURI(uri ...string) directive { // 4.9
	return wspList{"report-uri", uri}
}

// A security policy for a web resource.
type CSP struct {
	m map[string]directive
}

func New() *CSP {
	csp := new(CSP)
	csp.m = make(map[string]directive)
	return csp
}

// The default-src directive.
func (csp *CSP) DefaultSrc(src ...string) *CSP { // 4.1
	return csp.addDirective(defaultSrc(src...))
}

// The script-src directive.
func (csp *CSP) ScriptSrc(src ...string) *CSP { // 4.2
	return csp.addDirective(scriptSrc(src...))
}

// The object-src directive.
func (csp *CSP) ObjectSrc(src ...string) *CSP { // 4.3
	return csp.addDirective(objectSrc(src...))
}

// The style-src directive.
func (csp *CSP) StyleSrc(src ...string) *CSP { // 4.4
	return csp.addDirective(styleSrc(src...))
}

// The img-src directive.
func (csp *CSP) ImgSrc(src ...string) *CSP { // 4.5
	return csp.addDirective(imgSrc(src...))
}

// The media-src directive.
func (csp *CSP) MediaSrc(src ...string) *CSP { // 4.6
	return csp.addDirective(mediaSrc(src...))
}

// The frame-src directive.
func (csp *CSP) FrameSrc(src ...string) *CSP { // 4.7
	return csp.addDirective(frameSrc(src...))
}

// The font-src directive.
func (csp *CSP) FontSrc(src ...string) *CSP { // 4.8
	return csp.addDirective(fontSrc(src...))
}

// The connect-src directive.
func (csp *CSP) ConnectSrc(src ...string) *CSP { // 4.9
	return csp.addDirective(connectSrc(src...))
}

// The sandbox directive (TODO).
func (csp *CSP) Sandbox(test *CSP) *CSP { // 4.10 (Optional)
	return csp
}

// The report-uri directive.
func (csp *CSP) ReportURI(uri ...string) *CSP { // 4.11
	return csp.addDirective(reportURI(uri...))
}

func (csp *CSP) addDirective(d directive) *CSP {
	if csp.m == nil {
		csp.m = make(map[string]directive)
	}
	csp.m[d.Name()] = d
	return csp
}

// Encode the security policy as a string
func (csp *CSP) Encode() string {
	enc := make([]string, 0, len(csp.m))
	for _, dir := range csp.m {
		enc = append(enc, dir.EncodeDirective())
	}
	return strings.Join(enc, "; ")
}

// Set header's Content-Security-Policy to the encoded csp.
func (csp *CSP) Apply(header http.Header) {
	header.Set("Content-Security-Policy", csp.Encode())
}

// Apply csp on all responses served by handler
func Handler(csp *CSP, handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		csp.Apply(w.Header())
		handler.ServeHTTP(w, r)
	})
}

// See Handler().
func HandlerFunc(csp *CSP, handler http.HandlerFunc) http.Handler {
	return Handler(csp, handler)
}

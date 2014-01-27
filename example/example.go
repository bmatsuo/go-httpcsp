/*
An example instrumentation of github.com/bmatsuo/go-httpcsp.

	go run example.go

The example serves a CSP-protected website at http://localhost:8000. The landing
page has a bunch of tags telling the browser to load (and execute) content of
suspect origins. The security policy does not allow the browser to load the
resources, keeping the content on the page safe.

Other than the landing page modified security policies can be observed on paths
	/danger-zone
	/images
The page content is the same at all paths, but the varying policies allow
different content to be loaded.
*/
package main

import (
	"fmt"
	"log"
	"net/http"
	"sync/atomic"

	"github.com/bmatsuo/go-httpcsp"
)

func main() {
	addr := ":8000"
	fmt.Println("Serving requests at http://localhost" + addr)

	// define security policies with a chaining api.
	cspbase := httpcsp.New().
		DefaultSrc(httpcsp.SELF).
		ScriptSrc(httpcsp.NONE).
		ImgSrc(httpcsp.SELF).
		ReportURI("/policy/violation")
	fmt.Println("GLOBAL POLICY:", cspbase)


	// extend existing policies for localized exceptions to the global policy.
	cspimg := cspbase.ImgSrc("travis-ci.org", "api.travis-ci.org")
	cspinline := cspbase.ScriptSrc(httpcsp.UNSAFE_INLINE)
	fmt.Println("IMAGE EXCEPTION:", cspimg)
	fmt.Println("UNSAFE EXCEPTION:", cspinline)

	// more deeply nested middleware takes precedence.
	root := http.NewServeMux()
	root.Handle("/", http.HandlerFunc(Root))
	root.Handle("/images", cspimg.MustCompile().Middleware(http.HandlerFunc(Root)))
	root.Handle("/danger-zone", cspinline.MustCompile().Middleware(http.HandlerFunc(Root)))
	http.Handle("/", cspbase.MustCompile().Middleware(root))

	// the violation handler doesn't serve HTML and does not need CSP headers.
	http.Handle("/policy/violation", httpcsp.ViolationHandler(CSPViolation))

	http.ListenAndServe(addr, http.DefaultServeMux)
}

func Root(resp http.ResponseWriter, req *http.Request) {
	fmt.Fprint(resp, `
	<html>
	<body>
		<strong>Boom!</strong>
		<img src="https://travis-ci.org/bmatsuo/go-httpcsp.png?branch=master"/>
		<strong>Zing!</strong>
		<script type="text/javascript">alert("malicious stuff...");</script>
		<script type="text/javascript" src="http://example.com/malicious.js"></script>
	</body>
	</html>`)
}

func CSPViolation(resp http.ResponseWriter, v *httpcsp.Violation) {
	id := newViolationId()
	log.Printf("csp violation %d: %#v\n", id, v.CSP)
	fmt.Fprintf(resp, "violation id: %d", id)
}

// silly violation id generator
var vcount int64

func newViolationId() int64 {
	return atomic.AddInt64(&vcount, 1)
}

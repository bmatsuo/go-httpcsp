package main

import (
	"fmt"
	"net/http"

	"github.com/bmatsuo/go-httpcsp"
)

func main() {
	addr := ":8000"
	fmt.Println("Serving requests at http://localhost" + addr)

	// define security policies with a chaining api.
	csp := httpcsp.New().
		DefaultSrc(httpcsp.SELF).
		ScriptSrc(httpcsp.NONE).
		ImgSrc(httpcsp.SELF).
		ReportURI("/policy/violation")
	fmt.Println("GLOBAL POLICY:", csp)

	// extend existing policies for localized exceptions to the global policy.
	cspinline := csp.ScriptSrc(httpcsp.UNSAFE_INLINE)
	fmt.Println("UNSAFE EXCEPTION:", csp)

	base := http.NewServeMux()
	base.Handle("/", csp.MustCompile().Middleware(http.HandlerFunc(Root)))
	base.Handle("/danger-zone", cspinline.MustCompile().Middleware(http.HandlerFunc(Root)))

	http.Handle("/", base)

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

func CSPViolation(v *httpcsp.Violation) {
	fmt.Printf("violation: %#v\n", v.CSP)
}

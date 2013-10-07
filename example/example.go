package main

import (
	"fmt"
	"net/http"

	"github.com/bmatsuo/go-httpcsp"
)

func main() {
	addr := ":8000"
	fmt.Println("Serving requests at http://localhost" + addr)

	csp := httpcsp.New().
		DefaultSrc(httpcsp.NONE).
		ScriptSrc(httpcsp.SELF).
		ImgSrc(httpcsp.SELF).
		ReportURI("/policy/violation").
		MustCompile()

	fmt.Println("Content-Security-Policy:", csp)

	http.Handle("/", csp.Middleware(http.HandlerFunc(Root)))

	http.Handle("/policy/violation", httpcsp.ViolationHandler(CSPViolation))

	http.ListenAndServe(addr, http.DefaultServeMux)
}

func Root(resp http.ResponseWriter, req *http.Request) {
	fmt.Fprint(resp,
		`<html>
		<body>
		<strong>Boom!</strong>
		<img src="https://travis-ci.org/bmatsuo/go-httpcsp.png?branch=master"/>
		<strong>Zing!</strong>
		</body>
		</html>`)
}

func CSPViolation(v *httpcsp.Violation) {
	fmt.Printf("violation: %#v\n", v.CSP)
}

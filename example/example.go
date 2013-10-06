package main

import (
	"fmt"
	"net/http"

	"github.com/bmatsuo/go-httpcsp"
)

func main() {
	addr := ":8000"
	fmt.Println("Serving requests at http://localhost" + addr)

	csp := httpcsp.Make().
		DefaultSrc(httpcsp.SELF).
		ImgSrc(httpcsp.SELF).
		ReportURI("/policy/violation").
		MustFinalize()
	fmt.Println("Content-Security-Policy:", csp)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w,
			`<html>
			<body>
				<strong>Boom!</strong>
				<img src="https://travis-ci.org/bmatsuo/go-httpcsp.png?branch=master"/>
				<strong>Zing!</strong>
			</body>
			</html>`)
	})

	http.Handle("/policy/violation",
		httpcsp.ViolationHandler(func(v *httpcsp.Violation) {
			fmt.Printf("violation: %#v\n", v.CSP)
		}))

	http.ListenAndServe(addr, csp.Middleware(http.DefaultServeMux))
}

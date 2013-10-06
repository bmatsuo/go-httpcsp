package main

import (
	"fmt"
	"net/http"

	"github.com/bmatsuo/go-httpcsp"
)

func main() {
	addr := ":8000"
	fmt.Println("serving requests at http://localhost" + addr)

	csp := httpcsp.New().
		DefaultSrc(httpcsp.SELF).
		//ImgSrc(httpcsp.HTTPS).
		ImgSrc(httpcsp.SELF).
		ReportURI("/policy/violation")
	fmt.Println("Content-Security-Policy:", csp.Encode())

	http.Handle("/", httpcsp.HandlerFunc(csp, func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w,
				`<html>
					<body>
						<strong>Boom!</strong>
						<img src="https://travis-ci.org/bmatsuo/go-httpcsp.png?branch=master"/>
						<strong>Zing!</strong>
					</body>
				</html>`)
		}))

	http.Handle("/policy/violation",
		httpcsp.ViolationHandler(func(v *httpcsp.Violation, err error) {
			if err == nil {
				fmt.Printf("violation: %#v\n", v.CSP)
			} else {
				fmt.Printf("error parsing violation report: %v\n", err)
			}
		}))
	http.ListenAndServe(addr, http.DefaultServeMux)
}

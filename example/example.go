package main

import (
	"fmt"
	"net/http"

	"github.com/bmatsuo/go-httpcsp"
)

func main() {
	addr := ":8000"
	fmt.Println("serving requests at http://localhost" + addr)
	http.Handle("/policy/violation",
		httpcsp.ViolationHandler(func(v *httpcsp.Violation, err error) {
			if err == nil {
				fmt.Printf("violation: %#v\n", v.CSP)
			} else {
				fmt.Printf("error parsing violation report: %v\n", err)
			}
		}))
	http.HandleFunc("/", func(resp http.ResponseWriter, req *http.Request) {
		new(httpcsp.CSP).
			DefaultSrc(httpcsp.SELF).
			ImgSrc(httpcsp.HTTPS).
			ReportURI("/policy/violation").
			Apply(resp.Header())

		fmt.Fprint(resp, `
		<html>
		<body>
			<h1>Boom!</h1>
			<img src="http://dbfestivalcom.c.presscdn.com/wp-content/uploads/2013/08/Lorde.jpg"/>
		</body>
		</html>
		`)
	})
	http.ListenAndServe(addr, http.DefaultServeMux)
}

package httpcsp

import (
	"net/http"
	"strings"
)

type Policy []*Directive

type Directive struct {
	Name  string
	Value string
}

func Make() Policy {
	return make(Policy, 0)
}

// The default-src directive.
func (csp Policy) DefaultSrc(src ...string) Policy { // 4.1
	return csp.addDirectives("default-src", src)
}

// The script-src directive.
func (csp Policy) ScriptSrc(src ...string) Policy { // 4.2
	return csp.addDirectives("script-src", src)
}

// The object-src directive.
func (csp Policy) ObjectSrc(src ...string) Policy { // 4.3
	return csp.addDirectives("object-src", src)
}

// The style-src directive.
func (csp Policy) StyleSrc(src ...string) Policy { // 4.4
	return csp.addDirectives("style-src", src)
}

// The img-src directive.
func (csp Policy) ImgSrc(src ...string) Policy { // 4.5
	return csp.addDirectives("img-src", src)
}

// The media-src directive.
func (csp Policy) MediaSrc(src ...string) Policy { // 4.6
	return csp.addDirectives("media-src", src)
}

// The frame-src directive.
func (csp Policy) FrameSrc(src ...string) Policy { // 4.7
	return csp.addDirectives("frame-src", src)
}

// The font-src directive.
func (csp Policy) FontSrc(src ...string) Policy { // 4.8
	return csp.addDirectives("font-src", src)
}

// The connect-src directive.
func (csp Policy) ConnectSrc(src ...string) Policy { // 4.9
	return csp.addDirectives("connect-src", src)
}

// The sandbox directive.
func (csp Policy) Sandbox(token ...string) Policy { // 4.10 (Optional)
	return csp.addDirectives("sandbox", token)
}

// The report-uri directive.
func (csp Policy) ReportURI(uri ...string) Policy { // 4.11
	return csp.addDirectives("report-uri", uri)
}

func (csp Policy) addDirectives(name string, values []string) Policy {
	// duplicate to avoid slice append overwrites :(
	_csp := make(Policy, 0, len(csp)+len(values))
	_csp = append(_csp, csp...)
	for i := range values {
		_csp = append(_csp, &Directive{name, values[i]})
	}
	return _csp
}

func (csp Policy) Finalize() (FinalizedPolicy, error) {
	// group directives by name
	bucket := make(map[string][]string)
	for _, d := range csp {
		bucket[d.Name] = append(bucket[d.Name], d.Value)
	}

	// TODO validate directives

	// stringify directive groups
	dstrs := make([]string, 0, len(bucket))
	for k := range bucket {
		dstr := k
		dstr += " "
		dstr += strings.Join(bucket[k], " ")

		dstrs = append(dstrs, dstr)
	}
	finalized := FinalizedPolicy(strings.Join(dstrs, "; "))

	return finalized, nil
}

func (csp Policy) MustFinalize() FinalizedPolicy {
	final, err := csp.Finalize()
	if err != nil {
		panic(err)
	}
	return final
}

type FinalizedPolicy string

func (csp FinalizedPolicy) Apply(header http.Header) {
	header.Set("Content-Security-Policy", string(csp))
}

func (csp FinalizedPolicy) ApplyReportOnly(header http.Header) {
	header.Set("Content-Security-Policy-Report-Only", string(csp))
}

func (csp FinalizedPolicy) Middleware(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		csp.Apply(w.Header())
		handler.ServeHTTP(w, r)
	})
}

func (csp FinalizedPolicy) MiddlewareReportOnly() func(http.Handler) http.Handler {
	return func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			csp.ApplyReportOnly(w.Header())
			handler.ServeHTTP(w, r)
		})
	}
}

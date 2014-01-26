package httpcsp

import (
	"bytes"
	"fmt"
	"net/http"
	"sort"
)

// flag for testing
var _FIX_COMPILE_ORDER bool

type sortablePolicy Policy

func (sp sortablePolicy) Len() int           { return len(sp) }
func (sp sortablePolicy) Swap(i, j int)      { sp[i], sp[j] = sp[j], sp[i] }
func (sp sortablePolicy) Less(i, j int) bool { return sp[i].Name < sp[j].Name }

type Policy []*Directive

type Directive struct {
	Name   string
	Values []string
}

func (d *Directive) String() string {
	return fmt.Sprint(*d)
}

func New() Policy {
	return make(Policy, 0)
}

// The default-src directive.
func (csp Policy) DefaultSrc(src string, srcs ...string) Policy { // 4.1
	return csp.addDirectives("default-src", src, srcs)
}

// The script-src directive.
func (csp Policy) ScriptSrc(src string, srcs ...string) Policy { // 4.2
	return csp.addDirectives("script-src", src, srcs)
}

// The object-src directive.
func (csp Policy) ObjectSrc(src string, srcs ...string) Policy { // 4.3
	return csp.addDirectives("object-src", src, srcs)
}

// The style-src directive.
func (csp Policy) StyleSrc(src string, srcs ...string) Policy { // 4.4
	return csp.addDirectives("style-src", src, srcs)
}

// The img-src directive.
func (csp Policy) ImgSrc(src string, srcs ...string) Policy { // 4.5
	return csp.addDirectives("img-src", src, srcs)
}

// The media-src directive.
func (csp Policy) MediaSrc(src string, srcs ...string) Policy { // 4.6
	return csp.addDirectives("media-src", src, srcs)
}

// The frame-src directive.
func (csp Policy) FrameSrc(src string, srcs ...string) Policy { // 4.7
	return csp.addDirectives("frame-src", src, srcs)
}

// The font-src directive.
func (csp Policy) FontSrc(src string, srcs ...string) Policy { // 4.8
	return csp.addDirectives("font-src", src, srcs)
}

// The connect-src directive.
func (csp Policy) ConnectSrc(src string, srcs ...string) Policy { // 4.9
	return csp.addDirectives("connect-src", src, srcs)
}

// The sandbox directive.
func (csp Policy) Sandbox(token string, tokens ...string) Policy { // 4.10 (Optional)
	return csp.addDirectives("sandbox", token, tokens)
}

// The report-uri directive.
func (csp Policy) ReportURI(uri string, uris ...string) Policy { // 4.11
	return csp.addDirectives("report-uri", uri, uris)
}

func (csp Policy) addDirectives(name string, v string, vs []string) Policy {
	vs = append([]string{v}, vs...)
	n := len(csp)
	// three-index avoids overwrites at policy extension forking points
	return append(csp[:n:n], &Directive{name, vs})
}

// check the policy for errors and compact internal representations.
func (csp Policy) Check() (Policy, error) {
	// group directives by name
	bucket := make(map[string][]string)
	for _, d := range csp {
		bucket[d.Name] = append(bucket[d.Name], d.Values...)
	}

	// validate directives
	for dname, dvals := range bucket {
		var err error
		switch dname {
		case "sandbox":
			err = validateSandbox(dvals)
		case "report-uri":
			err = validateReportURI(dvals)
		default:
			err = _validateSourceList(dvals, false)
		}

		if err != nil {
			return nil, err
		}
	}

	if len(bucket) == len(csp) {
		return csp, nil
	}

	// compact directives
	_csp := make(Policy, 0, len(bucket))
	for dname, dvals := range bucket {
		dvals = compileList1(dvals)

		isNONE := len(dvals) == 1 && dvals[0] == NONE
		if isNONE && (dname == "report-uri" || dname == "sandbox") {
			// 'none' is not valid. omit directives entirely.
			continue
		}

		// don't use addDirective here for efficiency
		_csp = append(_csp, &Directive{dname, dvals})
	}

	if _FIX_COMPILE_ORDER {
		sort.Sort(sortablePolicy(_csp))
	}

	return _csp, nil
}

func compileList1(dvals []string) []string {
	var c []string
	for _, d := range dvals {
		switch {
		case d == NONE:
			c = []string{NONE}
		case len(c) == 0 || c[0] == NONE: // NONE implies len of 1
			c = []string{d}
		default:
			c = append(c, d)
		}
	}
	return c
}

func compileList(dvals []string) string {
	var c string
	for _, d := range dvals {
		switch {
		case d == NONE:
			c = NONE
		case c == NONE || c == "":
			c = d
		default:
			c = fmt.Sprintf("%s %s", c, d)
		}
	}
	return c
}

// Compile csp into a form that can be applied to response headers.
// Calls csp.Check() before constructing the CompiledPolicy
func (csp Policy) Compile() (CompiledPolicy, error) {
	_csp, err := csp.Check()
	if err != nil {
		return "", err
	}
	buf := new(bytes.Buffer)
	printed := false
	for _, d := range _csp {
		valstr := compileList(d.Values)
		if valstr == "" {
			continue
		}
		if printed {
			fmt.Fprint(buf, "; ")
		}
		fmt.Fprintf(buf, "%s %s", d.Name, valstr)
		printed = true
	}
	return CompiledPolicy(buf.String()), nil
}

func (csp Policy) MustCompile() CompiledPolicy {
	compiled, err := csp.Compile()
	if err != nil {
		panic(err)
	}
	return compiled
}

type CompiledPolicy string

func (csp CompiledPolicy) Apply(header http.Header) {
	header.Set("Content-Security-Policy", string(csp))
}

func (csp CompiledPolicy) ApplyReportOnly(header http.Header) {
	header.Set("Content-Security-Policy-Report-Only", string(csp))
}

func (csp CompiledPolicy) Middleware(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		csp.Apply(w.Header())
		handler.ServeHTTP(w, r)
	})
}

func (csp CompiledPolicy) MiddlewareReportOnly() func(http.Handler) http.Handler {
	return func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			csp.ApplyReportOnly(w.Header())
			handler.ServeHTTP(w, r)
		})
	}
}

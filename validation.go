package httpcsp

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

func validateReportURI(uri []string) error {
	for i := range uri {
		_, err := url.Parse(uri[i])
		if err != nil {
			return fmt.Errorf("invalid report uri: %q", uri[i])
		}
	}
	return nil
}

var sandboxNegPatt = simpleRegexp(
	`\x7F | [\x00-\x1F] | \x20 | \t | \n
	| [
		(	)	<	>	@
		,	;	:	\\	"
		/	\[	\]	?	=
		{	}
	]`)

// sandbox values are restricted from having control characters, space,
// and certain symbols.
func validateSandbox(flag []string) error {
	for i := range flag {
		if sandboxNegPatt.MatchString(flag[i]) {
			return fmt.Errorf("invalid sandbox token: %q", flag[i])
		}
	}
	return nil
}

func validateSourceList(src []string) error {
	if len(src) == 1 && src[0] == NONE { // i don't understand why this is none...
		return nil
	}
	for i := range src {
		err := validateSource(src[i])
		if err != nil {
			return err
		}
	}
	return nil
}

func validateSource(src string) error {
	switch {
	case src == SELF:
	case src == UNSAFE_INLINE:
	case src == UNSAFE_EVAL:
	case schemePatt.MatchString(src):
	case hostPatt.MatchString(src):
	default:
		return fmt.Errorf("unexpected source: %q", src)
	}
	return nil
}

func simpleRegexp(patt ...string) *regexp.Regexp {
	filterSpace := func(c rune) rune {
		if unicode.IsSpace(c) {
			return -1
		}
		return c
	}
	fullPatt := strings.Join(patt, "")
	fullPatt = strings.Map(filterSpace, fullPatt)
	return regexp.MustCompile(fullPatt)
}

var _schemePatt = `[A-Za-z]([A-Za-z]|\d|[+]|[-]|[.])*`
var _hostChar = `([A-Za-z]|\d|-)`

var schemePatt = simpleRegexp(`^`, _schemePatt, `[:]`, `$`)
var hostPatt = simpleRegexp(
	`^`,
	// scheme
	`(`, _schemePatt, ` [:][/][/])?`,
	// hostname
	`(`, `[*]`,
	`|`, `([*][.])?`, _hostChar, `+`, `([.]`, _hostChar, `+`, `)*`,
	`)`,
	// port
	`([:]`, `(\d+ | [*])`, `)?`,
	`$`)

package httpcsp

import (
	"fmt"
)

func init() {
	_FIX_COMPILE_ORDER = true
}

// Policies are built with a chaining API and compiled before being applied to
// a resource.
func Example_chaining() {
	csp := New().
		DefaultSrc(NONE).
		ImgSrc("*").
		Sandbox("allow-forms").
		MustCompile()

	fmt.Println(csp)
	// Output:
	// default-src 'none'; img-src *; sandbox allow-forms
}

// Policies derive other policies but are immutable-ish.
func Example_immutability() {
	cspBase := New().
		DefaultSrc(NONE).
		ImgSrc("*").
		Sandbox("allow-forms")

	cspDerived := cspBase.ScriptSrc(SELF)

	fmt.Println(cspBase.MustCompile())
	fmt.Println(cspDerived.MustCompile())
	// Output:
	// default-src 'none'; img-src *; sandbox allow-forms
	// default-src 'none'; img-src *; sandbox allow-forms; script-src 'self'
}

// The NONE value overrides previously declared directive values.
// Subsequent directive values are not affected.
func Example_none() {
	csp1 := New().
		DefaultSrc(NONE).
		ImgSrc("*").
		Sandbox("allow-forms")

	csp2 := csp1.
		DefaultSrc(SELF).
		ImgSrc(NONE)

	csp3 := csp1.Sandbox(NONE)
	csp4 := csp3.Sandbox("allow-popups")

	fmt.Println(csp1.MustCompile())
	fmt.Println(csp2.MustCompile())
	fmt.Println(csp3.MustCompile())
	fmt.Println(csp4.MustCompile())
	// Output:
	// default-src 'none'; img-src *; sandbox allow-forms
	// default-src 'self'; img-src 'none'; sandbox allow-forms
	// default-src 'none'; img-src *
	// default-src 'none'; img-src *; sandbox allow-popups
}

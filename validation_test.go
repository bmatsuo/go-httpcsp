// Copyright 2014, Bryan Matsuo. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// csp_test.go.go [created: Tue, 21 Jan 2014]

package httpcsp

import (
	yt "github.com/bmatsuo/yup/yuptype"
	//"github.com/bmatsuo/yup"

	"testing"
)

func TestValidateSource(t *testing.T) {
	for _, src := range []string{
		//NONE,
		SELF,
		UNSAFE_INLINE,
		UNSAFE_EVAL,
		"http:",
		"localhost",
		"example.com",
		"example.com:*",
		"example.com:4567",
		"https://example.com",
	} {
		yt.Nil(t, validateSource(src, true))
	}

	for _, src := range []string{
		"https://",
		"example.com/blah",
		"http://example.com/blah",
		"*://example.com",
	} {
		yt.Error(t, validateSource(src, true))
	}
}

func TestValidateSourceList(t *testing.T) {
	for _, src := range [][]string{
		{NONE},
		{SELF, UNSAFE_INLINE, "http:"},
		{"localhost", "example.com"},
	} {
		yt.Nil(t, validateSourceList(src))
	}

	for _, src := range [][]string{
		{},
		{NONE, "http:"},
		{SELF, "https://"},
		{"https://static.example.com", "example.com/blah", UNSAFE_INLINE},
		{"http://example.com/blah", "https://"},
	} {
		yt.Error(t, validateSourceList(src))
	}
}

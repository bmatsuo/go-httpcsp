// Copyright 2014, Bryan Matsuo. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// csp_test.go.go [created: Tue, 21 Jan 2014]

package httpcsp

import (
	yt "github.com/bmatsuo/yup/yuptype"
	//"github.com/bmatsuo/yup"

	"fmt"
	"testing"
)

var thetestcsp = New().
	DefaultSrc(NONE).
	ScriptSrc(UNSAFE_INLINE).
	ScriptSrc(UNSAFE_EVAL).
	ObjectSrc("localhost").
	StyleSrc("example.com").
	ImgSrc("example.com:*").
	MediaSrc("example.com:4567").
	FrameSrc("https://example.com").
	FontSrc("http://example.com:4321").
	ConnectSrc(SELF).
	Sandbox("mudpies!").
	ReportURI("http://example.com/reports")

func TestPolicy(t *testing.T) {
	yt.Equal(t, fmt.Sprint(thetestcsp),
		`[{default-src 'none'} {script-src 'unsafe-inline'} {script-src 'unsafe-eval'} {object-src localhost} {style-src example.com} {img-src example.com:*} {media-src example.com:4567} {frame-src https://example.com} {font-src http://example.com:4321} {connect-src 'self'} {sandbox mudpies!} {report-uri http://example.com/reports}]`)
}

func TestCompile(t *testing.T) {
	ccsp, err := thetestcsp.Compile()
	yt.Nil(t, err, "couldn't compile thetestcsp")
	yt.NotNil(t, ccsp)
}

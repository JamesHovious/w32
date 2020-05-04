// Copyright 2010-2012 The W32 Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package w32

import (
	"golang.org/x/sys/windows"
	"unsafe"
)

var (
	modshcore = windows.NewLazySystemDLL("Shcore.dll")

	getScaleFactorForMonitor = modshcore.NewProc("GetScaleFactorForMonitor")
)

func GetScaleFactorForMonitor(hMonitor HMONITOR, scale *int) HRESULT {
	ret, _, _ := getScaleFactorForMonitor.Call(
		uintptr(hMonitor),
		uintptr(unsafe.Pointer(scale)))

	return HRESULT(ret)
}

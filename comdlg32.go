// Copyright 2010-2012 The W32 Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package w32

import (
	"golang.org/x/sys/windows"
	"unsafe"
)

var (
	modcomdlg32 = windows.NewLazySystemDLL("comdlg32.dll")

	procCommDlgExtendedError = modcomdlg32.NewProc("CommDlgExtendedError")
	procGetOpenFileName      = modcomdlg32.NewProc("GetOpenFileNameW")
	procGetSaveFileName      = modcomdlg32.NewProc("GetSaveFileNameW")
)

func GetOpenFileName(ofn *OPENFILENAME) bool {
	ret, _, _ := procGetOpenFileName.Call(
		uintptr(unsafe.Pointer(ofn)))

	return ret != 0
}

func GetSaveFileName(ofn *OPENFILENAME) bool {
	ret, _, _ := procGetSaveFileName.Call(
		uintptr(unsafe.Pointer(ofn)))

	return ret != 0
}

func CommDlgExtendedError() uint {
	ret, _, _ := procCommDlgExtendedError.Call()

	return uint(ret)
}

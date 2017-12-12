// Copyright 2010-2012 The W32 Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package w32

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	modntdll = syscall.NewLazyDLL("ntdll.dll")

	procAlpcGetMessageAttribute          = modntdll.NewProc("AlpcGetMessageAttribute")
	procNtAlpcAcceptConnectPort          = modntdll.NewProc("NtAlpcAcceptConnectPort")
	procNtAlpcCancelMessage              = modntdll.NewProc("NtAlpcCancelMessage")
	procNtAlpcConnectPort                = modntdll.NewProc("NtAlpcConnectPort")
	procNtAlpcCreatePort                 = modntdll.NewProc("NtAlpcCreatePort")
	procNtAlpcDisconnectPort             = modntdll.NewProc("NtAlpcDisconnectPort")
	procNtAlpcSendWaitReceivePort        = modntdll.NewProc("NtAlpcSendWaitReceivePort")
	procRtlCreateUnicodeStringFromAsciiz = modntdll.NewProc("RtlCreateUnicodeStringFromAsciiz") // TODO
	procZwAllocateVirtualMemory          = modntdll.NewProc("ZwAllocateVirtualMemory")
)

// https://msdn.microsoft.com/en-us/library/windows/hardware/ff566416(v=vs.85).aspx
func ZwAllocateVirtualMemory(hProcess HANDLE, lpAddress int, zeroBits int, reSize int, flAllocationType int, flProtect int) (err error) {
	ret, _, err := procVirtualAllocEx.Call(
		uintptr(hProcess),
		uintptr(lpAddress),
		uintptr(zeroBits),
		uintptr(reSize),
		uintptr(flAllocationType),
		uintptr(flProtect))
	if int(ret) == 0 {
		return nil
	}
	return err
}

func NtAlpcCreatePort(pObjectAttributes *OBJECT_ATTRIBUTES, pPortAttributes *ALPC_PORT_ATTRIBUTES) (hPort HANDLE, e error) {

	ret, _, _ := procNtAlpcCreatePort.Call(
		uintptr(unsafe.Pointer(&hPort)),
		uintptr(unsafe.Pointer(pObjectAttributes)),
		uintptr(unsafe.Pointer(pPortAttributes)),
	)

	if ret != ERROR_SUCCESS {
		return hPort, fmt.Errorf("0x%x", ret)
	}

	return
}

func NtAlpcAcceptConnectPort(
	hSrvConnPort HANDLE,
	flags uint32,
	pObjAttr *OBJECT_ATTRIBUTES,
	pPortAttr *ALPC_PORT_ATTRIBUTES,
	pContext *AlpcPortContext,
	pConnReq *AlpcShortMessage,
	pConnMsgAttrs *ALPC_MESSAGE_ATTRIBUTES,
	accept uintptr,
) (hPort HANDLE, e error) {

	ret, _, _ := procNtAlpcAcceptConnectPort.Call(
		uintptr(unsafe.Pointer(&hPort)),
		uintptr(hSrvConnPort),
		uintptr(flags),
		uintptr(unsafe.Pointer(pObjAttr)),
		uintptr(unsafe.Pointer(pPortAttr)),
		uintptr(unsafe.Pointer(pContext)),
		uintptr(unsafe.Pointer(pConnReq)),
		uintptr(unsafe.Pointer(pConnMsgAttrs)),
		accept,
	)

	if ret != ERROR_SUCCESS {
		e = fmt.Errorf("0x%x", ret)
	}
	return
}

func NtAlpcSendWaitReceivePort(
	hPort HANDLE,
	flags uint32,
	sendMsg *AlpcShortMessage, // Should actually point to PORT_MESSAGE + payload
	sendMsgAttrs *ALPC_MESSAGE_ATTRIBUTES,
	recvMsg *AlpcShortMessage,
	recvBufLen *uint32,
	recvMsgAttrs *ALPC_MESSAGE_ATTRIBUTES,
	timeout *int64, // use native int64
) (e error) {

	ret, _, _ := procNtAlpcSendWaitReceivePort.Call(
		uintptr(hPort),
		uintptr(flags),
		uintptr(unsafe.Pointer(sendMsg)),
		uintptr(unsafe.Pointer(sendMsgAttrs)),
		uintptr(unsafe.Pointer(recvMsg)),
		uintptr(unsafe.Pointer(recvBufLen)),
		uintptr(unsafe.Pointer(recvMsgAttrs)),
		uintptr(unsafe.Pointer(timeout)),
	)

	if ret != ERROR_SUCCESS {
		e = fmt.Errorf("0x%x", ret)
	}
	return
}

func AlpcGetMessageAttribute(buf *ALPC_MESSAGE_ATTRIBUTES, attr uint32) unsafe.Pointer {

	ret, _, _ := procAlpcGetMessageAttribute.Call(
		uintptr(unsafe.Pointer(buf)),
		uintptr(attr),
	)
	return unsafe.Pointer(ret)
}

func NtAlpcCancelMessage(hPort HANDLE, flags uint32, pMsgContext *ALPC_CONTEXT_ATTR) (e error) {

	ret, _, _ := procNtAlpcCancelMessage.Call(
		uintptr(hPort),
		uintptr(flags),
		uintptr(unsafe.Pointer(pMsgContext)),
	)

	if ret != ERROR_SUCCESS {
		e = fmt.Errorf("0x%x", ret)
	}
	return
}

func NtAlpcDisconnectPort(hPort HANDLE, flags uint32) (e error) {

	ret, _, _ := procNtAlpcDisconnectPort.Call(
		uintptr(hPort),
		uintptr(flags),
	)

	if ret != ERROR_SUCCESS {
		e = fmt.Errorf("0x%x", ret)
	}
	return
}

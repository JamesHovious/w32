package w32

import "syscall"

var (
	modmsvcrt  = syscall.NewLazyDLL("msvcrt.dll")
	procMemCpy = modmsvcrt.NewProc("memcpy")
	procStrLen = modmsvcrt.NewProc("strlen")
)

// https://msdn.microsoft.com/en-us/library/aa246468(v=vs.60).aspx
func CopyMemory(dst uintptr, src uintptr, length int) {
	procMemCpy.Call(dst, src, uintptr(uint32(length)))
}

func StrLen(p uintptr) uintptr {
	rc, _, _ := procStrLen.Call(p)
	return rc
}

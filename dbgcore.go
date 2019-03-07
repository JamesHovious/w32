package w32

import "syscall"

var (
	moddbgcore        = syscall.NewLazyDLL("Dbgcore.dll")
	miniDumpWritedump = moddbgcore.NewProc("MiniDumpWriteDump")
)

func miniDumpWritedump(hHandle HANDLE, ProcessId DWORD, hFile HANDLE, DumpType MINIDUMP_TYPE, ExceptionParam PMINIDUMP_EXCEPTION_INFORMATION, UserStreamParam PMINIDUMP_USER_STREAM_INFORMATION, CallbackParam PMINIDUMP_CALLBACK_INFORMATION) err {
	return nil
}

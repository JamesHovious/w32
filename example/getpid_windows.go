// Adapted from https://gist.github.com/henkman/3083408
// This example will return the PID of LSASS.exe
<<<<<<< HEAD
// This example must be run with Administrator privileges
=======
// This example must be run with Administrator privilges
>>>>>>> origin/dev
package main

import (
	"fmt"
<<<<<<< HEAD
	"github.com/viaMorgoth/w32"
	"syscall"
	"unsafe"
=======
	"syscall"
	"unsafe"

	"github.com/viaMorgoth/w32"
>>>>>>> origin/dev
)

func main() {
	pid := GetPid("Explorer.EXE") // TODO make this case insensitive
	fmt.Println(pid)
}

func getModuleInfo(me32 *w32.MODULEENTRY32) string {
	procName := syscall.UTF16ToString(me32.SzModule[:])
	return procName
}

func isPid(process_name string, pid uint32) bool {
	snap := w32.CreateToolhelp32Snapshot(w32.TH32CS_SNAPMODULE, pid)
	if snap == 0 {
		return false
	}
	defer w32.CloseHandle(snap)

	var me32 w32.MODULEENTRY32
	me32.Size = uint32(unsafe.Sizeof(me32))
	if !w32.Module32First(snap, &me32) {
		return false
	}
	if getModuleInfo(&me32) == process_name {
		return true
	} else {
		for w32.Module32Next(snap, &me32) {
			if getModuleInfo(&me32) == process_name {
				return true
			}
		}
	}
	return false

}

func GetPid(process_name string) (pid uint32) {
	ps := make([]uint32, 255)
	var read uint32 = 0
	if !w32.EnumProcesses(ps, uint32(len(ps)), &read) {
		println("could not read processes")
		return
	}

	for _, p := range ps[:read/4] {
		if p == 0 {
			continue
		}
		if isPid(process_name, p) {
			pid = p
			return pid
		}
	}
	return pid
}

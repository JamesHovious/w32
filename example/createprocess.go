package main

import (
<<<<<<< HEAD
	"github.com/viaMorgoth/w32"
	"syscall"
=======
	//	"fmt"
	"github.com/viaMorgoth/w32"
	"syscall"
	//	"unsafe"
>>>>>>> origin/dev
)

func main() {

	var sI syscall.StartupInfo
	var pI syscall.ProcessInformation

	argv := syscall.StringToUTF16Ptr("c:\\windows\\system32\\calc.exe")

	err := syscall.CreateProcess(
		nil,
		argv,
		nil,
		nil,
		true,
		0,
		nil,
		nil,
		&sI,
		&pI)

	_ = err
	proc := "c:\\windows\\system32\\calc.exe"

	w32.CreateProcessA(nil, proc, nil, nil, true, 0, nil, nil, &sI, &pI)
<<<<<<< HEAD
=======
	//(argv0p, argvp, nil, nil, true, flags, createEnvBlock(attr.Env), dirp, si, pi)
>>>>>>> origin/dev
}

package main

import (
	"syscall"

	"github.com/JamesHovious/w32"
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
}

package main

import (
	"github.com/JamesHovious/w32"
	"golang.org/x/sys/windows"
	"unsafe"
)

//more info: https://docs.microsoft.com/en-us/windows/win32/learnwin32/your-first-windows-program
func main() {
	className := "Sample Window Class"
	inst := w32.GetModuleHandle(className)

	wc := w32.WNDCLASSEX{
		WndProc:   windows.NewCallback(wndProc),
		Instance:  inst,
		ClassName: windows.StringToUTF16Ptr(className),
	}
	wc.Size = uint32(unsafe.Sizeof(wc))

	w32.RegisterClassEx(&wc)

	hwnd := w32.CreateWindowEx(
		0,
		windows.StringToUTF16Ptr(className),
		windows.StringToUTF16Ptr("Title Here"),
		w32.WS_OVERLAPPEDWINDOW,
		w32.CW_USEDEFAULT, w32.CW_USEDEFAULT, w32.CW_USEDEFAULT, w32.CW_USEDEFAULT,
		0,
		0,
		inst,
		nil,
	)
	if hwnd == 0 {
		panic(w32.GetLastError())
	}

	w32.ShowWindow(hwnd, w32.SW_SHOW)

	msg := w32.MSG{}
	for w32.GetMessage(&msg, 0, 0, 0) != 0 {
		w32.TranslateMessage(&msg)
		w32.DispatchMessage(&msg)
	}
}

func wndProc(hwnd w32.HWND, msg uint32, wparam, lparam uintptr) uintptr {
	switch msg {
	case w32.WM_DESTROY:
		w32.PostQuitMessage(0)
	case w32.WM_PAINT:
		ps := w32.PAINTSTRUCT{}
		hdc := w32.BeginPaint(hwnd, &ps)
		w32.FillRect(hdc, &ps.RcPaint, w32.COLOR_WINDOW+1)
		w32.EndPaint(hwnd, &ps)
	}
	return w32.DefWindowProc(hwnd, msg, wparam, lparam)
}


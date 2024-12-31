package maldev

import (
	"syscall"
	"unsafe"
)

type LPVOID uintptr
type DWORD uint32
type SIZE_T uintptr
type HANDLE uintptr
type LPSECURITY_ATTRIBUTES uintptr
type LPTHREAD_START_ROUTINE uintptr

const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40
	PAGE_READWRITE         = 0x04
	MEM_RELEASE            = 0x8000
)

/*
LPVOID VirtualAlloc(

	[in, optional] LPVOID lpAddress,          // The starting address of the region to allocate (set to NULL)
	[in]           SIZE_T dwSize,             // The size of the region to allocate, in bytes
	[in]           DWORD  flAllocationType,   // The type of memory allocation
	[in]           DWORD  flProtect           // The memory protection for the region of pages to be allocated

);
*/
func VirtualAlloc(lpAddress LPVOID, dwSize SIZE_T, flAllocationType DWORD, flProtect DWORD) (LPVOID, error) {
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	virtualAlloc := kernel32.MustFindProc("VirtualAlloc")
	addr, _, ntStatus := virtualAlloc.Call(uintptr(lpAddress), uintptr(dwSize), uintptr(flAllocationType), uintptr(flProtect))
	err := NTStatusToError(NTSTATUS(ntStatus.(syscall.Errno)))
	if err != nil {
		return 1, err
	}
	return LPVOID(addr), nil
}

/*
BOOL VirtualProtect(

	[in]  LPVOID lpAddress,       // The base address of the memory region whose access protection is to be changed
	[in]  SIZE_T dwSize,          // The size of the region whose access protection attributes are to be changed, in bytes
	[in]  DWORD  flNewProtect,    // The new memory protection option
	[out] PDWORD lpflOldProtect   // Pointer to a 'DWORD' variable that receives the previous access protection value of 'lpAddress'

);
*/
func VirtualProtect(lpAddress LPVOID, dwSize SIZE_T, flNewProtect DWORD, lpflOldProtect *DWORD) (bool, error) {
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	virtualProtect := kernel32.MustFindProc("VirtualProtect")
	result, _, ntStatus := virtualProtect.Call(uintptr(lpAddress), uintptr(dwSize), uintptr(flNewProtect), uintptr(unsafe.Pointer(lpflOldProtect)))
	err := NTStatusToError(NTSTATUS(ntStatus.(syscall.Errno)))
	if err != nil {
		return false, err
	}
	return result != 0, nil
}

/*
HANDLE CreateThread(

	[in, optional]  LPSECURITY_ATTRIBUTES   lpThreadAttributes,    // Set to NULL - optional
	[in]            SIZE_T                  dwStackSize,           // Set to 0 - default
	[in]            LPTHREAD_START_ROUTINE  lpStartAddress,        // Pointer to a function to be executed by the thread, in our case its the base address of the payload
	[in, optional]  __drv_aliasesMem LPVOID lpParameter,           // Pointer to a variable to be passed to the function executed (set to NULL - optional)
	[in]            DWORD                   dwCreationFlags,       // Set to 0 - default
	[out, optional] LPDWORD                 lpThreadId             // pointer to a 'DWORD' variable that receives the thread ID (set to NULL - optional)

);
*/
func CreateThread(lpThreadAttributes LPSECURITY_ATTRIBUTES, dwStackSize SIZE_T, lpStartAddress LPTHREAD_START_ROUTINE, lpParameter LPVOID, dwCreationFlags DWORD, lpThreadId *DWORD) (HANDLE, error) {
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	createThread := kernel32.MustFindProc("CreateThread")
	handle, _, ntStatus := createThread.Call(uintptr(lpThreadAttributes), uintptr(dwStackSize), uintptr(lpStartAddress), uintptr(lpParameter), uintptr(dwCreationFlags), uintptr(unsafe.Pointer(lpThreadId)))
	err := NTStatusToError(NTSTATUS(ntStatus.(syscall.Errno)))
	if err != nil {
		return 1, err
	}
	return HANDLE(handle), nil
}

/*
BOOL VirtualFree(

	[in] LPVOID lpAddress,
	[in] SIZE_T dwSize,
	[in] DWORD  dwFreeType

);
*/
func VirtualFree(lpAddress LPVOID, dwSize SIZE_T, dwFreeType DWORD) (bool, error) {
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	virtualFree := kernel32.MustFindProc("VirtualFree")
	result, _, ntStatus := virtualFree.Call(uintptr(lpAddress), uintptr(dwSize), uintptr(dwFreeType))
	err := NTStatusToError(NTSTATUS(ntStatus.(syscall.Errno)))
	if err != nil {
		return false, err
	}
	return result != 0, nil
}

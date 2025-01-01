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
typedef struct tagPROCESSENTRY32 {
  DWORD     dwSize;
  DWORD     cntUsage;
  DWORD     th32ProcessID;              // The process ID
  ULONG_PTR th32DefaultHeapID;
  DWORD     th32ModuleID;
  DWORD     cntThreads;
  DWORD     th32ParentProcessID;        // Process ID of the parent process
  LONG      pcPriClassBase;
  DWORD     dwFlags;
  CHAR      szExeFile[MAX_PATH];        // The name of the executable file for the process
} PROCESSENTRY32;
*/

type ULONG_PTR uintptr
type CHAR byte
type LONG int32

const MAX_PATH = 260

type PROCESSENTRY32 struct {
	dwSize              DWORD
	cntUsage            DWORD
	th32ProcessID       DWORD
	th32DefaultHeapID   ULONG_PTR
	th32ModuleID        DWORD
	cntThreads          DWORD
	th32ParentProcessID DWORD
	pcPriClassBase      LONG
	dwFlags             DWORD
	szExeFile           [MAX_PATH]CHAR
}

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

/*
HANDLE CreateToolhelp32Snapshot(

	[in] DWORD dwFlags,
	[in] DWORD th32ProcessID

);
*/
func CreateToolhelp32Snapshot(dwFlags DWORD, th32ProcessID DWORD) (HANDLE, error) {
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	createToolhelp32Snapshot := kernel32.MustFindProc("CreateToolhelp32Snapshot")
	handle, _, ntStatus := createToolhelp32Snapshot.Call(uintptr(dwFlags), uintptr(th32ProcessID))
	err := NTStatusToError(NTSTATUS(ntStatus.(syscall.Errno)))
	if err != nil {
		return 1, err
	}
	return HANDLE(handle), nil
}

const (
	TH32CS_INHERIT      = 0x80000000                                        // Indicates that the snapshot handle is to be inheritable.
	TH32CS_SNAPALL      = 0x00000001 | 0x00000008 | 0x00000002 | 0x00000004 // 	Includes all processes and threads in the system, plus the heaps and modules of the process specified in th32ProcessID. Equivalent to specifying the TH32CS_SNAPHEAPLIST, TH32CS_SNAPMODULE, TH32CS_SNAPPROCESS, and TH32CS_SNAPTHREAD values combined using an OR operation ('|').
	TH32CS_SNAPHEAPLIST = 0x00000001                                        // Includes all heaps of the process specified in th32ProcessID in the snapshot. To enumerate the heaps, see Heap32ListFirst.
	TH32CS_SNAPMODULE   = 0x00000008                                        // Includes all modules of the process specified in th32ProcessID in the snapshot. To enumerate the modules, see Module32First. If the function fails with ERROR_BAD_LENGTH, retry the function until it succeeds. 64-bit Windows:  Using this flag in a 32-bit process includes the 32-bit modules of the process specified in th32ProcessID, while using it in a 64-bit process includes the 64-bit modules. To include the 32-bit modules of the process specified in th32ProcessID from a 64-bit process, use the TH32CS_SNAPMODULE32 flag.
	TH32CS_SNAPMODULE32 = 0x00000010                                        // Includes all 32-bit modules of the process specified in th32ProcessID in the snapshot when called from a 64-bit process. This flag can be combined with TH32CS_SNAPMODULE or TH32CS_SNAPALL. If the function fails with ERROR_BAD_LENGTH, retry the function until it succeeds.
	TH32CS_SNAPPROCESS  = 0x00000002                                        // Includes all processes in the system in the snapshot. To enumerate the processes, see Process32First.
	TH32CS_SNAPTHREAD   = 0x00000004                                        // Includes all threads in the system in the snapshot. To enumerate the threads, see Thread32First. To identify the threads that belong to a specific process, compare its process identifier to the th32OwnerProcessID member of the THREADENTRY32 structure when enumerating the threads.
)

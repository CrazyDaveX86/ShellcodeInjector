# pragma once
# include <stdio.h>
# include <windows.h>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define OBJ_CASE_INSENSITIVE 0x00000040L
#define FILE_NON_DIRECTORY_FILE        0x00000040
#define FILE_SYNCHRONOUS_IO_NONALERT   0x00000020
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define BUFFER_SIZE 0x40000
#define MAX_SHELLCODE_SIZE 1048

#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);        \
    (p)->RootDirectory = r;                         \
    (p)->Attributes = a;                            \
    (p)->ObjectName = n;                            \
    (p)->SecurityDescriptor = s;                    \
    (p)->SecurityQualityOfService = NULL;           \
}

//----------------------------------------------------------------------

# define yapBad(msg, ...) printf("[*-*] " msg "\n", __VA_ARGS__)
# define yapInfo(msg, ...) printf("['-'] " msg "\n", __VA_ARGS__)
# define yapOkay(msg, ...) printf("[+-+] " msg "\n", __VA_ARGS__)

//----------------------------------------------------------------------

BOOL ShellcodeInjection(int PID, char* filename);
int findPID(char* Proc);

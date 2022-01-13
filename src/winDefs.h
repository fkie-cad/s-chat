#ifndef _WIN_DEFS_H
#define _WIN_DEFS_H

#include <windows.h>
#include <winternl.h>


#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

#define STATUS_SUCCESS               ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL          ((NTSTATUS)0xC0000001L)
#define STATUS_BUFFER_TOO_SMALL      ((NTSTATUS)0xC0000023L)
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xC0000034L)

#endif

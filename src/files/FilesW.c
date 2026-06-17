#include <stdio.h>
#include <direct.h>

#include <strsafe.h>

#include "../shared/Fifo.h"
#include "../shared/print.h"

#include "filesW.h"



int actOnFilesInDirW(
    _In_ WCHAR* Path, 
    _In_ FileCallback Cb, 
    _In_opt_ char** Types, 
    _In_ uint32_t Flags, 
    _In_ void* Params, 
    _In_ int* Killed
)
{
    FEnter();

    HANDLE hFind = INVALID_HANDLE_VALUE;
    WIN32_FIND_DATAW ffd;
    wchar_t* mask = L"*";
    wchar_t spec[MAX_PATH];
    wchar_t* path;
    Fifo directories;
    int s = 1;
    PFifoEntry entry;
    (Types);
    int recursive = (Flags & FILES_FLAG_RECURSIVE) > 0;
    
    DPrintW(L"  Path: %s\n", Path);

    if ( !ntDirExists(Path) )
    {
        return 0;
    }

    Fifo_init(&directories);
    Fifo_push(&directories, Path, (size_t)wcslen(Path)*2+2);

    while (!Fifo_empty(&directories) && !(*Killed))
    {
        entry = Fifo_front(&directories);
        path = (WCHAR*)entry->value;
        
        DPrintW(L" - path: %ws\n", path);
        memset(spec, 0, MAX_PATH * 2);
        StringCchPrintfW(spec, MAX_PATH, L"%ws\\%ws", path, mask);
        DPrintW(L" - spec: %s\n", spec);

        hFind = FindFirstFileW(spec, &ffd);
        if ( hFind == INVALID_HANDLE_VALUE )
        {
            s = 0;
            break;
        }
        do
        {
            if (wcscmp(ffd.cFileName, L".") != 0 &&
                wcscmp(ffd.cFileName, L"..") != 0)
            {
                memset(spec, 0, MAX_PATH * 2);
                DPrintW(L" - - path: %ws\n", path);
                DPrintW(L" - - ffd.cFileName: %ws\n", ffd.cFileName);
                StringCchPrintfW(spec, MAX_PATH, L"%ws\\%s", path, ffd.cFileName);
                spec[MAX_PATH - 1] = 0;
                if ( (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) )
                {
                    if ( !recursive )
                        continue;
                    
                    DPrintW(L" - - dir: %ws\n", spec);
                    s = (BOOL)Fifo_push(&directories, spec, (size_t)wcslen(spec) * 2 + 2);
                    DPrintW(L" - - fifo size: %d\n", s);
                    if (s == 0)
                    {
                        printf("Fifo push error!\n");
                        break;
                    }
                }
                else
                {
                    DPrintW(L" - - file: %ws\n", spec);
                    Cb(spec, ffd.cFileName, Params);
                }
            }
        }
        while ( FindNextFileW(hFind, &ffd) != 0 && !(*Killed) );

        if (GetLastError() != ERROR_NO_MORE_FILES)
        {
            FindClose(hFind);
            s = 1;
            break;
        }

        Fifo_pop_front(&directories);

        FindClose(hFind);
        hFind = INVALID_HANDLE_VALUE;
    }
    
    Fifo_destroy(&directories);

    FLeave();
    return s;
}

ULONG ntGetFullPathName(
    _In_ PWCHAR FileName,
    _In_ ULONG BufferLength,
    _Out_writes_bytes_(BufferLength) PWSTR Buffer,
    _Out_opt_ PWSTR *FilePart
)
{
    INT s;
    
    if ( FilePart )
        *FilePart = NULL;

    if ( !BufferLength )
        return 0;
    Buffer[0] = 0;

    if ( BufferLength < 5 )
    {
        //SetLastError(ERROR_BUFFER_OVERFLOW);
        return 0;
    }
    *(PUINT64)Buffer = NT_PATH_PREFIX_W;
    BufferLength -= 8;
    Buffer += 4;

    // wants and returns cb
    s = RtlGetFullPathName_U(FileName, BufferLength, Buffer, FilePart);

    return s + 8;
}

BOOLEAN ntFileExists(
    _In_ WCHAR* Path
)
{
    return ntPathExists(Path, FALSE);
}

BOOLEAN ntDirExists(
    _In_ WCHAR* Path
)
{
    return ntPathExists(Path, TRUE);
}

/**
 */
BOOLEAN ntPathExists(
    _In_ WCHAR* Path, 
    _In_ BOOLEAN checkAsDir
)
{
    FILE_NETWORK_OPEN_INFORMATION info;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING uName;
    ULONG fileAttr = 0;

    FEnter();

    if ( NULL == Path ) 
        return FALSE;
    
    RtlZeroMemory(&uName, sizeof(UNICODE_STRING));
    RtlZeroMemory(&info, sizeof(FILE_NETWORK_OPEN_INFORMATION));
    RtlZeroMemory(&objAttr, sizeof(OBJECT_ATTRIBUTES));

    RtlInitUnicodeString(
        &uName, 
        Path
    );

    InitializeObjectAttributes(
        &objAttr, 
        &uName, 
        OBJ_CASE_INSENSITIVE, 
        NULL, 
        NULL
    );

    status = NtQueryFullAttributesFile(
                    &objAttr, 
                    &info
                );

    if ( !NT_SUCCESS(status) )
    {
        return FALSE;
    }

    fileAttr = info.FileAttributes;

    if ( checkAsDir )
    {
        return (fileAttr & FILE_ATTRIBUTE_DIRECTORY) > 0;
    }
    else
    {
        return !((fileAttr & FILE_ATTRIBUTE_DIRECTORY));
    }
}

NTSTATUS ntOpenFile(
    _In_ PWCHAR Path, 
    _Out_ PHANDLE Handle, 
    _In_ ULONG OpenAccess, 
    _In_ ULONG CreateDisposion
)
{
    NTSTATUS status = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK iosb;
    UNICODE_STRING uni_Filename;
    
    RtlZeroMemory(&objAttr, sizeof(objAttr));
    RtlZeroMemory(&iosb, sizeof(iosb));

    RtlInitUnicodeString(&uni_Filename, Path);
    
    InitializeObjectAttributes(
        &objAttr, 
        &uni_Filename, 
        OBJ_CASE_INSENSITIVE, 
        NULL, 
        NULL
    );

    *Handle = NULL;

    if ( CreateDisposion == 0 )
        if ( OpenAccess == NT_FILE_READ_ACCESS )
            CreateDisposion = FILE_OPEN;
        else if ( OpenAccess == NT_FILE_WRITE_ACCESS )
            CreateDisposion = FILE_OPEN_IF;
        
    status = NtCreateFile(
                Handle, 
                OpenAccess, 
                &objAttr, 
                &iosb, 
                NULL, 
                FILE_ATTRIBUTE_NORMAL, 
                FILE_SHARE_READ, 
                CreateDisposion,
                FILE_SYNCHRONOUS_IO_NONALERT, 
                NULL,
                0
            );

    return status;
}

NTSTATUS ntGetFileSize(
    _In_ HANDLE Handle,
    _Out_ PUINT64 Size
)
{
    NTSTATUS status = STATUS_SUCCESS;
    IO_STATUS_BLOCK iosb;
    FILE_STANDARD_INFORMATION fi;
    
    *Size = 0;
    RtlZeroMemory(&iosb, sizeof(iosb));

    status = NtQueryInformationFile(Handle, &iosb, (PVOID) &fi, sizeof(fi), FileStandardInformation);
    
    if ( !NT_SUCCESS(status) ) 
    {
        return status;
    }

    *Size = fi.EndOfFile.QuadPart;

    return status;
}

NTSTATUS ntGetFileBytes(
    _In_ PWCHAR Path, 
    _Inout_ PUINT8* Output, 
    _Inout_ PULONG OutputSize
)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE file = NULL;
    UINT64 fileSize = 0;
    PUINT8 fileBuffer = NULL;
    
    IO_STATUS_BLOCK iosb = {0};


    status = ntOpenFile(Path, &file, NT_FILE_READ_ACCESS, 0);
    if ( !NT_SUCCESS(status) )
    {
        EPrint("Could not open file \"%ws\"! (0x%x)\n", Path, status);
        goto clean;
    }

    status = ntGetFileSize(file, &fileSize);
    if ( !NT_SUCCESS(status) )
    {
        EPrint("GetFileSize for \"%ws\" failed! (0x%x)\n", Path, status);
        goto clean;
    }
    if ( fileSize >= (ULONG)-1 )
    {
        status = STATUS_BUFFER_TOO_SMALL;
        EPrint("File \"%ws\" too big! (0x%x)\n", Path, status);
        goto clean;
    }
    if ( fileSize == 0 )
    {
        status = STATUS_INVALID_PARAMETER;
        EPrint("File \"%ws\" too small! (0x%x)\n", Path, status);
        goto clean;
    }
    
    if ( *Output == NULL )
    {
        fileBuffer = (PUINT8)malloc(fileSize);
        if ( fileBuffer == NULL )
        {
            status = STATUS_NO_MEMORY;
            EPrint("Allocating buffer failed! (0x%x)\n", status);
            goto clean;
        }
    }
    else
    {
        if ( *OutputSize < (ULONG)fileSize )
        {
            status = STATUS_BUFFER_TOO_SMALL;
            EPrint("File \"%ws\" too big for buffer! (0x%x)\n", Path, status);
            goto clean;
        }
        fileBuffer = *Output;
    }


    status = NtReadFile(file, NULL, NULL, NULL, &iosb, fileBuffer, (ULONG)fileSize, NULL, NULL);
    if ( status != 0 )
    {
        EPrint("NtReadFile failed! (0x%x)\n", status);
        goto clean;
    }
    

    *OutputSize = (ULONG) iosb.Information;
    if ( *Output == NULL )
    {
        *Output = fileBuffer;
    }

clean:
    if (file)
        NtClose(file);

    return status;
}

NTSTATUS ntWriteFileBytes(
    _In_ PWCHAR Path, 
    _In_ PUINT8 Input, 
    _In_ ULONG InputSize
)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE file = NULL;
    
    IO_STATUS_BLOCK iosb = {0};


    status = ntOpenFile(Path, &file, NT_FILE_WRITE_ACCESS, FILE_OVERWRITE_IF);
    if ( !NT_SUCCESS(status) )
    {
        EPrint("Could not open file \"%ws\"! (0x%x)\n", Path, status);
        goto clean;
    }

    status = NtWriteFile(file, NULL, NULL, NULL, &iosb, Input, InputSize, NULL, NULL);
    if ( status != 0 )
    {
        EPrint("NtWriteFile failed! (0x%x)\n", status);
        goto clean;
    }
    
clean:
    if (file)
        NtClose(file);

    return status;
}

void cropTrailingSlashW(_Inout_ wchar_t* path)
{
    size_t n = wcslen(path);
    if ( n == 0 )
        return;
    if ( path[n-1] == L'/' )
        path[n-1] = 0;
#ifdef _WIN32
    if ( path[n-1] == L'\\' )
        path[n-1] = 0;
#endif
}

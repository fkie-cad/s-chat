#ifndef MESSAGE_HANDLER_H
#define MESSAGE_HANDLER_H

#include <stdio.h>
#include <stdint.h>

#include "filetransfer.h"



extern FILE* out;
extern const char* file_dir;

extern const char* nick;
extern char other_name[MAX_NAME_LN];

extern FT_RECV_OBJECTS ft_recv_obj;



int handleMessage(
    _In_ PVOID data, 
    _In_ ULONG dataSize,
    _In_ SecPkgContext_StreamSizes* pSizes,
    _In_ ULONG type,
    _Inout_ BOOL* running
);

int cancelFileReceive();

int cleanFileReceive(
    bool success
);

#endif

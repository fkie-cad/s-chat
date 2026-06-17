#ifndef MESSAGE_HANDLER_H
#define MESSAGE_HANDLER_H

#include <stdio.h>
#include <stdint.h>

#include "filetransfer.h"

#define JOIN_TIMEOUT (1000)


#include "../utils/Logger.h"
extern Logger logger;
extern size_t loggerId;

extern const char* file_dir;

extern const char* nick;
extern char other_name[MAX_NAME_LN];

extern FT_RECV_OBJECTS ft_recv_obj;
extern FT_RECV_OBJECTS ft_send_obj;



int handleMessage(
    _In_ PVOID data, 
    _In_ ULONG dataSize,
    _In_ SecPkgContext_StreamSizes* pSizes,
    _In_ ULONG type,
    _Inout_ BOOL* running
);

void reapRecvThread();

int cancelFileReceive();

int cleanFileReceive(
    bool success
);

#endif

#ifndef FILE_TRANSFER_H
#define FILE_TRANSFER_H


#include <Windows.h>
#include "../schannel/sec.h"

#include <stdio.h>

#include <mutex>

#include "../schannel/connection.h"

#define FT_INFO_LABEL_SENDING "sending"
#define FT_INFO_LABEL_RECEIVED "received"
#define FT_INFO_LABEL_CANCELED "canceled"

typedef struct _FILE_TRANSFER_DATA {
    char name[MAX_NAME_LN];
    FILE* file;
    size_t size;
    size_t written;
    size_t path_ln;
    char path[1];
} FILE_TRANSFER_DATA, *PFILE_TRANSFER_DATA;

typedef struct _FT_RECEIVE_THREAD_DATA {
    PFILE_TRANSFER_DATA ftd;
    const char* name;
    SOCKET Socket;
    CtxtHandle Context;
    SecPkgContext_StreamSizes* Sizes;
    PBYTE pbIoBuffer;
    ULONG cbIoBuffer;
    INT type;
    BOOL* running;
} FT_RECEIVE_THREAD_DATA, *PFT_RECEIVE_THREAD_DATA;

typedef struct _FT_SEND_THREAD_DATA {
    CHAR ip[MAX_IP_LN];
    CHAR port[MAX_PORT_LN];
    size_t file_size;
    ADDRESS_FAMILY family;
    size_t path_ln;
    char path[1];
} FT_SEND_THREAD_DATA, *PFT_SEND_THREAD_DATA;

#define FT_FLAG_ACTIVE  (0x1)
#define FT_FLAG_RUNNING (0x2)
#define FT_FLAG_CANCEL  (0x4)
typedef struct _FT_OBJECTS {
    CtxtHandle Context; //
    SOCKET Socket;
    HANDLE thread;
    ULONG thread_id;
    UINT32 flags;
    BOOL running;
} FT_OBJECTS, *PFT_OBJECTS,
FT_SEND_OBJECTS, *PFT_SEND_OBJECTS,
FT_RECV_OBJECTS, *PFT_RECV_OBJECTS;


#include "../utils/Logger.h"
extern Logger logger;
extern size_t loggerId;

extern char* target_ip;
extern char* target_port;
extern ADDRESS_FAMILY family;

extern uint8_t other_cert_hash[SHA256_BYTES_LN];

extern CredHandle hClientCreds;
extern CredHandle hServerCreds;

extern SOCKET ListenSocket;


void initFTObject(
    _Out_ PFT_OBJECTS obj
);

void showSentFileInfo(
    _In_ const char* label,
    _In_opt_ uint8_t* sha256,
    _In_ size_t size,
    _In_ const char* base_name,
    _In_ size_t base_name_ln,
    _In_ const char* name,
    _In_ bool self
);

void sendReceivedFileInfo(
    _In_ bool success,
    _In_ const char* path, 
    _In_ const char* label,
    _In_ const char* name,
    _In_ bool self,
    _In_ SOCKET Socket,
    _In_ PCtxtHandle phContext,
    _In_ SecPkgContext_StreamSizes* pSizes,
    _In_ PBYTE pbIoBuffer,
    _In_ ULONG cbIoBuffer
);

int sendAcceptedFileInfo(
    _In_ bool accepted,
    _In_ const char* name,
    _In_ const char* path,
    _In_ size_t path_ln,
    _In_ SOCKET Socket,
    _In_ PCtxtHandle phContext,
    _In_ SecPkgContext_StreamSizes* pSizes,
    _In_ PBYTE pbIoBuffer,
    _In_ ULONG cbIoBuffer
);

int saveFile(
    _In_ PFILE_TRANSFER_DATA ftd, 
    _In_ uint8_t* buffer, 
    _In_ size_t buffer_ln
);

/**
 * FT receive data thread
 * Accept or connect socket and receive the data.
 */
ULONG WINAPI recvFTDataThread(
    LPVOID lpParam
);

/**
 * Disconnect ft connection initiated by the receiving socket
 */
int disconnectFTRecvSocket(
    _Inout_ SOCKET* Socket,
    _Inout_ PCtxtHandle Context,
    _In_ PCredHandle Creds,
    _In_ INT type
);

#endif

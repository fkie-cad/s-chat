#ifndef SCHANNEL_CONNECTION_H
#define SCHANNEL_CONNECTION_H

#ifndef GUI
#include <winsock2.h>
#endif
#include <windows.h>

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "../values.h"
#include "common.h"
#include "../guiBridge.h"



#define MAX_CONN (0x1)

#define IO_BUFFER_SIZE  (0x10000)
#define RECEIVE_LOOP_SLEEP (0x80)
#define SEND_LOOP_SLEEP (0x100)




extern FILE* out;
extern const char* file_dir;

extern PSecurityFunctionTable g_pSSPI;

extern HCERTSTORE hMyCertStore;

extern BOOL fClientAuth;



BOOL
initSecurityInterface();

SECURITY_STATUS
CreateCredentials(
    _In_ LPSTR certId,
    _Out_ PCredHandle phCreds,
    _In_ ULONG credFlags,
    _In_ ULONG fCredentialUse
);

SECURITY_STATUS
PerformClientHandshake(
    _In_ SOCKET Socket,
    _In_ PCredHandle phCreds,
    _In_ LPSTR ServerIp,
    _Out_ CtxtHandle *phContext,
    _Out_ SecBuffer *pExtraData
);

LONG
VerifyServerCertificate(
    _In_ PCCERT_CONTEXT pServerCert,
    _In_ PSTR ServerIp,
    _In_ DWORD CertFlags
);

/**
 * Check negotiated TLS version and maybe other crypto params.
 * Update to only TLS1.3 if available.
 */
INT
CheckConnectionInfo(
    _In_ CtxtHandle *phContext,
    _In_ PSecurityFunctionTable SSPI
);

SECURITY_STATUS
sendSChannelData(
    _In_ PUCHAR pbMessage,
    _In_ ULONG cbMessage,
    _In_ SOCKET Socket,
    _In_ CtxtHandle *phContext,
    _In_ SecPkgContext_StreamSizes* pSizes,
    _In_ PBYTE pbIoBuffer,
    _In_ ULONG cbIoBuffer
);

/**
 * Reveive loop
 * 
 * @param Socket
 * @param phClientCreds PCredHandle client creds if server wants renegotiantion ( client only )
 * @param
 * @param
 * @param
 */
SECURITY_STATUS
receiveSChannelData(
    _In_ SOCKET Socket,
    _In_ PCredHandle phClientCreds,
    _In_ PCtxtHandle phContext,
    _In_ SecPkgContext_StreamSizes* pSizes,
    _Inout_ PBYTE pbIoBuffer,
    _In_ ULONG cbIoBuffer,
    _In_ ULONG type,
    _In_ BOOL* running
);

INT
readStreamEncryptionProperties(
    _Out_ SecPkgContext_StreamSizes* pSizes,
    _In_ CtxtHandle *phContext
);

INT
readStreamEncryptionProperties(
    _Out_ SecPkgContext_StreamSizes* pSizes,
    _In_ CtxtHandle *phContext
);

INT
allocateBuffer(
    _In_ SecPkgContext_StreamSizes* pSizes,
    _Out_ PBYTE* pbBuffer,
    _Out_ ULONG* cbBuffer
);

BOOL
SSPINegotiateLoop(
    _In_ SOCKET Socket,
    _Out_ PCtxtHandle phContext,
    _In_ PCredHandle phCred,
    _In_ BOOL fDoInitialRead,
    _In_ BOOL NewContext,
    _In_ PBYTE pbIoBuffer,
    _In_ ULONG cbIoBuffer
);

//LONG
//DisconnectFromClient(
//    SOCKET Socket, 
//    PCredHandle phCreds,
//    CtxtHandle *phContext
//);

/**
 * Send close notify to the other side.
 * Close socket and delete context. 
 */
LONG
Disconnect(
    _Inout_ SOCKET* Socket, 
    _In_ PCredHandle phCreds,
    _Inout_ CtxtHandle *phContext,
    _In_ ULONG type
);

LONG
VerifyClientCertificate(
    _In_ PCCERT_CONTEXT Cert,
    _In_ DWORD CertFlags
);

void SChannel_clean(
    _Out_ PCtxtHandle Context,
    _Out_ PCredHandle ClientCreds,
    _Out_ PCredHandle ServerCreds,
    _Out_ HCERTSTORE* CertStore
);

void deleteCreds(
    _Out_ PCredHandle Creds
);

void 
deleteSecurityContext(
    _Out_ CtxtHandle *phContext
);

#endif

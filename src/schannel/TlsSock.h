#ifndef TLS_SOCK_H
#define TLS_SOCK_H

#include "sec.h"



extern FILE* out;
extern const char* cert_dir;



/**
 * Accept a TLS socket client connecton.
 *
 * @param 
 * @param 
 * @param 
 * @param 
 * @param 
 * @param 
 * @param CertHash uint8_t[SHA256_BYTES_LN] preallocated buffer
 */
int acceptTLSSocket(
    _In_ SOCKET Listener,
    _Out_ SOCKET* CSocket,
    _Out_ PCtxtHandle Context,
    _In_ PCredHandle Creds,
    _In_ PBYTE pbIoBuffer,
    _In_ ULONG cbIoBuffer,
    _Out_ uint8_t* CertHash,
    _Out_ SOCKADDR_STORAGE* addr,
    _Out_ socklen_t* addr_ln
);

/**
 * Connect a TLS socket to its server.
 *
 * @param 
 * @param 
 * @param 
 * @param 
 * @param 
 * @param 
 * @param CertHash uint8_t[SHA256_BYTES_LN] preallocated buffer
 */
int connectTLSSocket(
    _In_ char* ip, 
    _In_ char* port,
    _In_ ADDRESS_FAMILY family,
    _Out_ SOCKET* Socket,
    _Out_ PCtxtHandle Context,
    _In_ PCredHandle Creds,
    _Out_ uint8_t* CertHash
);

int hashCert(
    _In_ PCCERT_CONTEXT cert, 
    _Out_ uint8_t* bytes
);

#endif

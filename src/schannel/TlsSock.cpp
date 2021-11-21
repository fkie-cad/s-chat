#include "../net/sock.h"

#include "TlsSock.h"

#include "../dbg.h"
#include "connection.h"
#include "../crypto/windows/HasherCNG.h"



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
)
{
#ifdef DEBUG_PRINT
    fprintf(out, "acceptTLSSocket()\n");
#endif
    if ( Listener == INVALID_SOCKET )
    {
        fprintf(out, "Listener is invalid\n");
        return SCHAT_ERROR_INVALID_SOCKET;
    }
    int s = 0;
    SYSTEMTIME sts;

    //SOCKADDR_STORAGE addr;
    //socklen_t addr_ln = sizeof(SOCKADDR_STORAGE);
    *addr_ln = sizeof(SOCKADDR_STORAGE);

    PCCERT_CONTEXT pRemoteCertContext = NULL;

    // Accept a client socket
    fprintf(out, "waiting for connection...\n");
    *CSocket = accept(Listener, (PSOCKADDR)addr, addr_ln);
    if ( *CSocket == INVALID_SOCKET )
    {
        s = getLastSError();
        fprintf(out, " - accept failed with error: 0x%x\n", s);
        return SCHAT_ERROR_INVALID_SOCKET;
    }
    GetLocalTime(&sts);
    fprintf(out, "connection accepted %02d.%02d.%04d %02d:%02d:%02d\n------------------------------------------------------------------\n",
        sts.wDay, sts.wMonth, sts.wYear, 
        sts.wHour, sts.wMinute, sts.wSecond);
    if ( *addr_ln > 0)
    {
        fprintf(out, "Connected Client Info:\n");
        printSockAddr(addr, (int)*addr_ln, out);
    }
    
    // Perform handshake
    s = SSPINegotiateLoop(
            *CSocket,
            Context,
            Creds,
            TRUE,
            TRUE,
            pbIoBuffer,
            cbIoBuffer
        );
    if ( !s )
    {
        fprintf(out, "ERROR (0x%x): SSPINegotiateLoop\n", s);
        s = SCHAT_ERROR_SERVER_HANDSHAKE;
        goto clean;
    }

    if ( fClientAuth )
    {
        // Read the client certificate.
        s = g_pSSPI->QueryContextAttributes(Context,
                                        SECPKG_ATTR_REMOTE_CERT_CONTEXT,
                                        (PVOID)&pRemoteCertContext);
        if ( s != SEC_E_OK )
        {
            fprintf(out, "ERROR (0x%x): querying client certificate\n", s);
            s = SCHAT_ERROR_QUERY_REMOTE_CERT;
            goto clean;
        }

#ifdef DEBUG_PRINT_HEX_DUMP
        printCert(pRemoteCertContext, out);
#endif

        char hash[SHA1_STRING_BUFFER_LN];
        hashCert(pRemoteCertContext, CertHash, hash);
        fprintf(out, "sha1 of certificate: %s\n", hash);
#ifdef GUI
        showCertSha(hash);
#endif
        s = saveCert(pRemoteCertContext, hash, cert_dir, out);
        if ( s != 0 )
        {
            fprintf(out, "ERROR (0x%x): Saving client cert failed.\n", s);
            s = SCHAT_ERROR_SAVE_CERT;
            goto clean;
        }

        DisplayCertChain(pRemoteCertContext, TRUE, out);

        // Attempt to validate client certificate.
        // may be skipped due to manual verification
        s = VerifyClientCertificate(pRemoteCertContext, 0);
        if ( s )
        {
            fprintf(out, "ERROR (0x%lx): authenticating client credentials\n", s);
            //s = SCHAT_ERROR_VERIFY_CERTIFICATE;
            goto clean;
        }
#ifdef DEBUG_PRINT
        else
            fprintf(out, "\nAuth succeeded, ready for command\n");
#endif
    }

    s = CheckConnectionInfo(Context, g_pSSPI);
    if ( s != 0 )
    {
        fprintf(out, "ERROR (0x%x): CheckConnectionInfo failed!\n", s);
        s = SCHAT_ERROR_TLS_VERSION;
        goto clean;
    }

    DisplayConnectionInfo(Context, g_pSSPI, out);
    fprintf(out, "\n");

clean:
    if ( pRemoteCertContext )
    {
        CertFreeCertificateContext(pRemoteCertContext);
        pRemoteCertContext = NULL;
    }

    return s;
}

int connectTLSSocket(
    _In_ char* ip, 
    _In_ char* port,
    _In_ ADDRESS_FAMILY family,
    _Out_ SOCKET* Socket,
    _Out_ PCtxtHandle Context,
    _In_ PCredHandle Creds,
    _Out_ uint8_t* CertHash
)
{
    int s = 0;

    PADDRINFOA addr_info = NULL;
    
    PCCERT_CONTEXT remoteCertContext = NULL; //
    
#ifdef DEBUG_PRINT
    fprintf(out, "connectTLSSocket()\n");
#endif

    s = initConnection(&addr_info, family, ip, port, Socket, AI_NUMERICHOST, out);
    if ( s != 0 )
    {
        fprintf(out, "initConnection failed with error: 0x%x\n", s);
        s = SCHAT_ERROR_INIT_CONNECTION;
        goto clean;
    }

    s = connect(*Socket , addr_info->ai_addr, (int)addr_info->ai_addrlen);
    if ( s != 0 )
    {
        s = getLastSError();
        fprintf(out, "connectSock failed with error: 0x%x\n", s);
        s = SCHAT_ERROR_CONNECT;
        goto clean;
    }
    
    SecBuffer ExtraData; // nothing done with it ??
    ExtraData.cbBuffer = 0;
    s = PerformClientHandshake(
            *Socket,
            Creds,
            ip,
            Context,
            &ExtraData
        );
    if ( s != 0  )
    {
        fprintf(out, "ERROR (0x%x): performing handshake (%s)\n", s, getSecErrorString(s));
        s = SCHAT_ERROR_CLIENT_HANDSHAKE;
        goto clean;
    }
    if ( ExtraData.cbBuffer != 0 )
    {
        fprintf(out, "INFO: 0x%x bytes of unhandled extra data received in handshake.\n", ExtraData.cbBuffer);
    }

    // Get server's certificate.
    s = g_pSSPI->QueryContextAttributes(Context,
                                        SECPKG_ATTR_REMOTE_CERT_CONTEXT,
                                        (PVOID)&remoteCertContext);
    if ( s != SEC_E_OK )
    {
        fprintf(out, "ERROR (0x%x): Querying remote certificate\n", s);
        s = SCHAT_ERROR_QUERY_REMOTE_CERT;
        goto clean;
    }

#ifdef DEBUG_PRINT_HEX_DUMP
    fprintf(out, "CertStore: %p", hMyCertStore);
    printCert(remoteCertContext, out);
#endif
    
    char hash[SHA1_STRING_BUFFER_LN];
    hashCert(remoteCertContext, CertHash, hash);
    fprintf(out, "sha1 of certificate: %s\n", hash);
#ifdef GUI
    showCertSha(hash);
#endif
    s = saveCert(remoteCertContext, hash, cert_dir, out);
    if ( s != 0 )
    {
        fprintf(out, "ERROR (0x%x): saving certificate\n", s);
        s = SCHAT_ERROR_SAVE_CERT;
        goto clean;
    }
    
    // Display server certificate chain.
    DisplayCertChain(remoteCertContext, FALSE, out);

    // Attempt to validate server certificate.
    // may be skipped because of manual verification
    s = VerifyServerCertificate(
        remoteCertContext,
        ip,
        0
    );
    if ( s != 0 )
    {
        fprintf(out, "skipping!\n");
        fprintf(out, "ERROR (0x%x): authenticating server credentials!\n", s);
//        goto cleanup;
    }
    
    // Free the server certificate context.
    CertFreeCertificateContext(remoteCertContext);
    remoteCertContext = NULL;

    s = CheckConnectionInfo(Context, g_pSSPI);
    if ( s != 0 )
    {
        fprintf(out, "ERROR (0x%x): CheckConnectionInfo failed!\n", s);
        s = SCHAT_ERROR_TLS_VERSION;
        goto clean;
    }

    DisplayConnectionInfo(Context, g_pSSPI, out);
    fprintf(out, "\n");

clean:
    if ( addr_info != NULL )
        freeaddrinfo(addr_info);

    return s;
}

void hashCert(
    _In_ PCCERT_CONTEXT cert, 
    _Out_ uint8_t* bytes,
    _Out_ char* str
)
{
    int s;

    s = sha1Buffer(cert->pbCertEncoded, cert->cbCertEncoded, bytes, SHA1_BYTES_LN);
    if ( s != 0 )
    {
        fprintf(out, "ERROR (0x%x): Calculating hash failed!\n", s);
#ifdef GUI
        showStatus("ERROR: Calculating hash failed!\n");
#endif
        return;
    }

    hashToString(bytes, SHA1_BYTES_LN, str, SHA1_STRING_BUFFER_LN);
}

#include "../net/sock.h"

#include "../values.h"
#include "TlsSock.h"

#include "../dbg.h"
#include "connection.h"



int acceptTLSSocket(
    _In_ SOCKET Listener,
    _Out_ SOCKET* CSocket,
    _Out_ PCtxtHandle Context,
    _In_ PCredHandle Creds,
    _In_ PBYTE pbIoBuffer,
    _In_ ULONG cbIoBuffer,
    _Out_writes_(CERT_HASH_BYTES_LN) uint8_t* CertHash,
    _Out_ SOCKADDR_STORAGE* Addr,
    _Out_ socklen_t* AddrLn
)
{
    int s = 0;
    SYSTEMTIME sts;

#ifdef DEBUG_PRINT
    logger.logInfo(loggerId, 0, "acceptTLSSocket()\n");
#endif

    if ( Listener == INVALID_SOCKET )
    {
        s = SCHAT_ERROR_INVALID_SOCKET;
        logger.logError(loggerId, s, "Listener is invalid\n");
        return s;
    }

    //SOCKADDR_STORAGE addr;
    //socklen_t addr_ln = sizeof(SOCKADDR_STORAGE);
    *AddrLn = sizeof(SOCKADDR_STORAGE);

    PCCERT_CONTEXT remoteCertContext = NULL;

    // Accept a client socket
    logger.logInfo(loggerId, 0, "Waiting for connection...\n");
    *CSocket = accept(Listener, (PSOCKADDR)Addr, AddrLn);
    if ( *CSocket == INVALID_SOCKET )
    {
        s = getLastSError();
        logger.logError(loggerId, s, "  accept failed.\n");
        return SCHAT_ERROR_INVALID_SOCKET;
    }
    GetLocalTime(&sts);
    logger.logInfo(loggerId, 0, "Connection accepted %02d.%02d.%04d %02d:%02d:%02d\n------------------------------------------------------------------\n",
        sts.wDay, sts.wMonth, sts.wYear, 
        sts.wHour, sts.wMinute, sts.wSecond);
    if ( *AddrLn > 0 )
    {
        logger.logInfo(loggerId, 0, "Connected Client Info:\n");
        printSockAddr(Addr, (int)*AddrLn);
    }

    // Perform handshake
    s = SSPINegotiateLoop(
            *CSocket,
            Context,
            Creds,
            TRUE,
            TRUE,
            pbIoBuffer,
            cbIoBuffer,
            0
        );
    if ( !s )
    {
        logger.logError(loggerId, s, "SSPINegotiateLoop\n");
        s = SCHAT_ERROR_SERVER_HANDSHAKE;
        goto clean;
    }

    if ( fClientAuth )
    {
        // Read the client certificate.
        s = g_pSSPI->QueryContextAttributes(Context,
                                        SECPKG_ATTR_REMOTE_CERT_CONTEXT,
                                        (PVOID)&remoteCertContext);
        if ( s != SEC_E_OK )
        {
            logger.logError(loggerId, s, "querying client certificate\n");
            s = SCHAT_ERROR_QUERY_REMOTE_CERT;
            goto clean;
        }

#ifdef DEBUG_PRINT_HEX_DUMP
        printCert(remoteCertContext);
#endif

        hashCert(remoteCertContext, CertHash);
        char hash[CERT_HASH_STRING_BUFFER_LN];
        hashToString(CertHash, CERT_HASH_BYTES_LN, hash, CERT_HASH_STRING_BUFFER_LN);
        logger.logInfo(loggerId, 0, "hash of certificate: %s\n", hash);

        s = saveCert(remoteCertContext, hash, cert_dir);
        if ( s != 0 )
        {
            logger.logError(loggerId, s, "Saving client cert failed.\n");
            s = SCHAT_ERROR_SAVE_CERT;
            goto clean;
        }

        DisplayCertChain(remoteCertContext, TRUE);

        // Attempt to validate client certificate.
        // may be skipped due to manual verification
        s = VerifyClientCertificate(remoteCertContext, 0);
        if ( s )
        {
            logger.logError(loggerId, s, "authenticating client credentials\n");
            //s = SCHAT_ERROR_VERIFY_CERTIFICATE;
            goto clean;
        }
#ifdef DEBUG_PRINT
        else
            logger.logInfo(loggerId, 0, "\nAuth succeeded, ready for command\n");
#endif
    }

    s = CheckConnectionInfo(Context, g_pSSPI);
    if ( s != 0 )
    {
        logger.logError(loggerId, s, "CheckConnectionInfo failed!\n");
        s = SCHAT_ERROR_TLS_VERSION;
        goto clean;
    }

    DisplayConnectionInfo(Context, g_pSSPI);
    logger.logInfo(loggerId, 0, "\n");

clean:
    if ( remoteCertContext )
    {
        CertFreeCertificateContext(remoteCertContext);
        remoteCertContext = NULL;
    }

    return s;
}

int connectTLSSocket(
    _In_ char* Ip, 
    _In_ char* Port,
    _In_ ADDRESS_FAMILY Family,
    _Out_ SOCKET* Socket,
    _Out_ PCtxtHandle Context,
    _In_ PCredHandle Creds,
    _Out_writes_(CERT_HASH_BYTES_LN) uint8_t* CertHash
)
{
    int s = 0;

    PADDRINFOA addr_info = NULL;
    
    PCCERT_CONTEXT remoteCertContext = NULL; //
    
#ifdef DEBUG_PRINT
    logger.logInfo(loggerId, 0, "connectTLSSocket()\n");
#endif

    RtlZeroMemory(CertHash, CERT_HASH_BYTES_LN);

    s = initConnection(&addr_info, Family, Ip, Port, Socket, AI_NUMERICHOST);
    if ( s != 0 )
    {
        logger.logError(loggerId, s, "initConnection failed.\n");
        s = SCHAT_ERROR_INIT_CONNECTION;
        goto clean;
    }

    s = connect(*Socket , addr_info->ai_addr, (int)addr_info->ai_addrlen);
    if ( s != 0 )
    {
        s = getLastSError();
        logger.logError(loggerId, s, "connectSock failed.\n");
        s = SCHAT_ERROR_CONNECT;
        goto clean;
    }
    
    SecBuffer ExtraData; // nothing done with it ??
    ExtraData.cbBuffer = 0;
    s = PerformClientHandshake(
            *Socket,
            Creds,
            Ip,
            Context,
            &ExtraData
        );
    if ( s != 0  )
    {
        logger.logError(loggerId, s, "performing handshake (%s)\n", getSecErrorString(s));
        s = SCHAT_ERROR_CLIENT_HANDSHAKE;
        goto clean;
    }
    if ( ExtraData.cbBuffer != 0 )
    {
        logger.logInfo(loggerId, 0, "INFO: 0x%x bytes of unhandled extra data received in handshake.\n", ExtraData.cbBuffer);
    }

    // Get server's certificate.
    s = g_pSSPI->QueryContextAttributes(Context,
                                        SECPKG_ATTR_REMOTE_CERT_CONTEXT,
                                        (PVOID)&remoteCertContext);
    if ( s != SEC_E_OK )
    {
        logger.logError(loggerId, s, "Querying remote certificate\n");
        s = SCHAT_ERROR_QUERY_REMOTE_CERT;
        goto clean;
    }

#ifdef DEBUG_PRINT_HEX_DUMP
    logger.logInfo(loggerId, 0, "CertStore: %p", hMyCertStore);
    printCert(remoteCertContext);
#endif
    
    hashCert(remoteCertContext, CertHash);

    char hash[CERT_HASH_STRING_BUFFER_LN];
    hashToString(CertHash, CERT_HASH_BYTES_LN, hash, CERT_HASH_STRING_BUFFER_LN);
    logger.logInfo(loggerId, 0, "hash of certificate: %s\n", hash);

    s = saveCert(remoteCertContext, hash, cert_dir);
    if ( s != 0 )
    {
        logger.logError(loggerId, s, "saving certificate\n");
        s = SCHAT_ERROR_SAVE_CERT;
        goto clean;
    }
    
    // Display server certificate chain.
    DisplayCertChain(remoteCertContext, FALSE);

    // Attempt to validate server certificate.
    // may be skipped because of manual verification
    s = VerifyServerCertificate(
        remoteCertContext,
        Ip,
        0
    );
    if ( s != 0 )
    {
        logger.logInfo(loggerId, 0, "skipping!\n");
        logger.logError(loggerId, s, "authenticating server credentials!\n");
//        goto cleanup;
    }
    
    // Free the server certificate context.
    CertFreeCertificateContext(remoteCertContext);
    remoteCertContext = NULL;

    s = CheckConnectionInfo(Context, g_pSSPI);
    if ( s != 0 )
    {
        logger.logError(loggerId, s, "CheckConnectionInfo failed!\n");
        s = SCHAT_ERROR_TLS_VERSION;
        goto clean;
    }

    DisplayConnectionInfo(Context, g_pSSPI);
    logger.logInfo(loggerId, 0, "\n");

clean:
    if ( addr_info != NULL )
        freeaddrinfo(addr_info);

    return s;
}

int hashCert(
    _In_ PCCERT_CONTEXT Cert, 
    _Out_writes_(CERT_HASH_BYTES_LN) uint8_t* Bytes
)
{
    int s;
    
#if CERT_HASH_TYPE == CERT_HASH_TYPE_SHA1
    s = sha1Buffer(Cert->pbCertEncoded, Cert->cbCertEncoded, Bytes, CERT_HASH_BYTES_LN);
#elif CERT_HASH_TYPE == CERT_HASH_TYPE_SHA256
    s = sha256Buffer(Cert->pbCertEncoded, Cert->cbCertEncoded, Bytes, CERT_HASH_BYTES_LN);
#endif
    if ( s != 0 )
    {
        logger.logError(loggerId, s, "Calculating hash failed!\n");
        return SCHAT_ERROR_CALCULATE_HASH;
    }

    return 0;
}

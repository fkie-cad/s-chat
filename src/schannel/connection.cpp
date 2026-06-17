#include "connection.h"


#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "../dbg.h"
#include "../guiBridge.h"
#include "../utils/Converter.h"
#include "../crypto/windows/HasherCNG.h"
#include "../engine/MessageHandler.h"



static
SECURITY_STATUS
ClientHandshakeLoop(
    _In_ SOCKET Socket,
    _In_ PCredHandle Creds,
    _Inout_ CtxtHandle *Context,
    _In_ BOOL fDoInitialRead,
    _Out_ SecBuffer *pExtraData
);



BOOL
initSecurityInterface()
{
    g_pSSPI = InitSecurityInterfaceA();

    if ( g_pSSPI == NULL )
    {
        logger.logError(loggerId, GetLastError(), "reading security interface.\n");
        return FALSE;
    }

    return TRUE;
}

SECURITY_STATUS
CreateCredentials(
    _In_ LPSTR certId,
    _Out_ PCredHandle Creds,
    _In_ ULONG credFlags,
    _In_ ULONG fCredentialUse
)
{
    TimeStamp tsExpiry;
    SECURITY_STATUS status = SEC_E_OK;
    PCCERT_CONTEXT pCertContext = NULL;
    SCH_CREDENTIALS schCreds;
    
    Creds->dwLower = 0;
    Creds->dwUpper = 0;

    if ( certId == NULL )
    {
        status = SEC_E_NO_CREDENTIALS;
        logger.logError(loggerId, status, "Missing certificate identifier\n");
        return status;
    }

    if ( hMyCertStore == NULL )
    {
        hMyCertStore = CertOpenSystemStoreA(0, "MY");

        if ( !hMyCertStore )
        {
            status = GetLastError();
            logger.logError(loggerId, status, "CertOpenSystemStore\n");
            return status;
        }
    }

    uint8_t hash_data[SHA1_BYTES_LN];
    uint8_t* hash_ptr = hash_data; // passing &hash_data to function does not work
    status = parsePlainBytes(certId, &hash_ptr, SHA1_BYTES_LN);
    if ( status != 0 )
    {
        logger.logError(loggerId, status, "parsePlainBytes\n");
        goto cleanup;
    }

    CRYPT_HASH_BLOB hash;
    ZeroMemory(&hash, sizeof(hash));
    hash.cbData = SHA1_BYTES_LN;
    hash.pbData = hash_data;

    pCertContext = CertFindCertificateInStore(
                        hMyCertStore, 
                        X509_ASN_ENCODING, 
                        0,
                        CERT_FIND_HASH,
                        &hash,
                        NULL
                    );
    if ( pCertContext == NULL )
    {
        logger.logError(loggerId, GetLastError(), "CertFindCertificateInStore\n");
        return SEC_E_NO_CREDENTIALS;
    }

    // throws error, if tls 1_2 is disabled
    //TLS_PARAMETERS tlsParams;
    //ZeroMemory(&tlsParams, sizeof(tlsParams));
    //tlsParams.grbitDisabledProtocols = SP_PROT_TLS1_0 | 
    //                                   SP_PROT_TLS1_1 |
    //                                   SP_PROT_TLS1_2;

    ZeroMemory(&schCreds, sizeof(schCreds));
    schCreds.dwVersion  = SCH_CREDENTIALS_VERSION;
    schCreds.cCreds = 1;
    schCreds.paCred = &pCertContext;
    schCreds.dwFlags |= credFlags;
    //schCreds.cTlsParameters = 1;
    //schCreds.pTlsParameters = &tlsParams;
    schCreds.dwSessionLifespan = 10; // 0 for default of 36000000 milliseconds (ten hours)

    // Create an SSPI credential.
    status = g_pSSPI->AcquireCredentialsHandleA(
                        NULL,                   // Name of principal    
                        //TLS1SP_NAME_A,    // Name of package
                        //SCHANNEL_NAME_A,    // Name of package
                        //(CHAR*)DEFAULT_TLS_SSP_NAME_A,    // Name of package
                        (CHAR*)UNISP_NAME_A,    // Name of package
                        fCredentialUse,   // Flags indicating use
                        NULL,                   // Pointer to logon ID
                        &schCreds,          // Package specific data
                        NULL,                   // Pointer to GetKey() func
                        NULL,                   // Value to pass to GetKey()
                        Creds,                // (out) Cred Handle
                        &tsExpiry);             // (out) Lifetime (optional)
    if ( status != SEC_E_OK )
    {
        logger.logError(loggerId, status, "%s returned by AcquireCredentialsHandle\n", getSecErrorString(status));
        goto cleanup;
    }

    SYSTEMTIME sts;
    FileTimeToSystemTime(
        (FILETIME*)&tsExpiry,
        &sts
    );
    logger.logInfo(loggerId, 0, "cred expire: %02d.%02d.%04d %02d:%02d:%02d\n\n", 
        sts.wDay, sts.wMonth, sts.wYear, sts.wHour, sts.wMinute, sts.wSecond);

    //printCert(pCertContext);

cleanup:
    // Free the certificate context. Schannel has already made its own copy.
    if ( pCertContext )
    {
        CertFreeCertificateContext(pCertContext);
    }

    if ( hMyCertStore )
    {
        CertCloseStore(hMyCertStore, 0);
        hMyCertStore = NULL;
    }

    return status;
}

SECURITY_STATUS
PerformClientHandshake(
    _In_ SOCKET Socket,
    _In_ PCredHandle Creds,
    _In_ LPSTR ServerIp,
    _Out_ CtxtHandle *Context,
    _Out_ SecBuffer *pExtraData
)
{
    SecBufferDesc outBuffer;
    SecBuffer outBuffers[1];
    DWORD dwSSPIFlags;
    DWORD dwSSPIOutFlags;
    TimeStamp tsExpiry;
    SECURITY_STATUS scRet;
    DWORD cbData;

    ZeroMemory(pExtraData, sizeof(SecBuffer));

    dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT   |
                  ISC_REQ_REPLAY_DETECT     |
                  ISC_REQ_CONFIDENTIALITY   |
                  ISC_RET_EXTENDED_ERROR    |
                  ISC_REQ_ALLOCATE_MEMORY   |
                  //ISC_REQ_MANUAL_CRED_VALIDATION   | // client
                  //ISC_REQ_USE_SUPPLIED_CREDS  | // client
                  ISC_REQ_STREAM;

    //
    //  Initiate a ClientHello message and generate a token.
    //

    outBuffers[0].pvBuffer = NULL;
    outBuffers[0].BufferType = SECBUFFER_TOKEN;
    outBuffers[0].cbBuffer = 0;

    outBuffer.cBuffers = 1;
    outBuffer.pBuffers = outBuffers;
    outBuffer.ulVersion = SECBUFFER_VERSION;

    scRet = g_pSSPI->InitializeSecurityContextA(
                    Creds,
                    NULL,
                    ServerIp,
                    dwSSPIFlags,
                    0,
                    0,
                    NULL,
                    0,
                    Context,
                    &outBuffer,
                    &dwSSPIOutFlags,
                    &tsExpiry);

    if ( scRet != SEC_I_CONTINUE_NEEDED )
    {
        logger.logError(loggerId, scRet, "InitializeSecurityContext (1)\n");
        return scRet;
    }

    // Send response to server if there is one.
    if ( outBuffers[0].cbBuffer != 0 && outBuffers[0].pvBuffer != NULL )
    {
        cbData = send(Socket,
                      (PCHAR)outBuffers[0].pvBuffer,
                      outBuffers[0].cbBuffer,
                      0);
        if ( cbData == SOCKET_ERROR || cbData == 0 )
        {
            logger.logError(loggerId, WSAGetLastError(), "Sending hello data to server (1)\n");
            g_pSSPI->FreeContextBuffer(outBuffers[0].pvBuffer);
            deleteSecurityContext(Context);
            return SEC_E_INTERNAL_ERROR;
        }

#ifdef DEBUG_PRINT
        logger.logInfo(loggerId, 0, "0x%x bytes of handshake data sent\n", cbData);
#endif
#ifdef DEBUG_PRINT_HEX_DUMP
        PrintHexDump(cbData, outBuffers[0].pvBuffer);
        logger.logInfo(loggerId, 0, "\n");
#endif

        // Free output buffer.
        g_pSSPI->FreeContextBuffer(outBuffers[0].pvBuffer);
        outBuffers[0].pvBuffer = NULL;
    }


    return ClientHandshakeLoop(Socket, Creds, Context, TRUE, pExtraData);
}

static
SECURITY_STATUS
ClientHandshakeLoop(
    _In_ SOCKET Socket,
    _In_ PCredHandle Creds,
    _Inout_ CtxtHandle *Context,
    _In_ BOOL fDoInitialRead,
    _Out_ SecBuffer *pExtraData
)
{
    SecBufferDesc inBuffer;
    SecBuffer inBuffers[2];
    SecBufferDesc outBuffer;
    SecBuffer outBuffers[1];
    DWORD dwSSPIFlags;
    DWORD dwSSPIOutFlags;
    TimeStamp tsExpiry;
    SECURITY_STATUS scRet;
    DWORD cbData;

    PUCHAR IoBuffer;
    DWORD cbIoBuffer;
    BOOL fDoRead;

    RtlZeroMemory(pExtraData, sizeof(*pExtraData));


    dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT   |
                  ISC_REQ_REPLAY_DETECT     |
                  ISC_REQ_CONFIDENTIALITY   |
                  ISC_RET_EXTENDED_ERROR    |
                  ISC_REQ_ALLOCATE_MEMORY   |
                  ISC_REQ_STREAM;

    //
    // Allocate data buffer.
    //
    ULONG IoBufferSize = IO_BUFFER_SIZE;
    IoBuffer = (PUCHAR) LocalAlloc(LMEM_FIXED, IoBufferSize);
    if ( IoBuffer == NULL )
    {
        scRet = SEC_E_INTERNAL_ERROR;
        logger.logError(loggerId, scRet, "Out of memory (1)\n");
        return scRet;
    }
    cbIoBuffer = 0;

    fDoRead = fDoInitialRead;

    // 
    // Loop until the handshake is finished or an error occurs.
    //

    scRet = SEC_I_CONTINUE_NEEDED;

    while ( scRet == SEC_I_CONTINUE_NEEDED        ||
            scRet == SEC_E_INCOMPLETE_MESSAGE     ||
            scRet == SEC_I_INCOMPLETE_CREDENTIALS ) 
    {
        // Read data from server.
        if ( 0 == cbIoBuffer || scRet == SEC_E_INCOMPLETE_MESSAGE )
        {
            if ( fDoRead )
            {
                cbData = recv(Socket, 
                              (PCHAR)(IoBuffer + cbIoBuffer), 
                              IoBufferSize - cbIoBuffer, 
                              0);
                if ( cbData == SOCKET_ERROR )
                {
                    logger.logError(loggerId, WSAGetLastError(), "reading data from server\n");
                    scRet = WSAGetLastError();
                    break;
                }
                else if ( cbData == 0 )
                {
                    scRet = WSAECONNRESET;
                    logger.logError(loggerId, scRet, "Server unexpectedly disconnected\n");
                    break;
                }

#ifdef DEBUG_PRINT
                logger.logInfo(loggerId, 0, "0x%x bytes of handshake data received\n", cbData);
#endif
#ifdef DEBUG_PRINT_HEX_DUMP
                PrintHexDump(cbData, IoBuffer + cbIoBuffer);
                logger.logInfo(loggerId, 0, "\n");
#endif

                cbIoBuffer += cbData;
            }
            else
            {
                fDoRead = TRUE;
            }
        }


        //
        // Set up the input buffers. 
        // Buffer 0 is used to pass in data received from the server. 
        // Schannel will consume some or all of this. 
        // Buffer 1 will contain leftover data (if any) and
        // given a buffer type of SECBUFFER_EXTRA.
        //

        inBuffers[0].pvBuffer   = IoBuffer;
        inBuffers[0].cbBuffer   = cbIoBuffer;
        inBuffers[0].BufferType = SECBUFFER_TOKEN;

        inBuffers[1].pvBuffer   = NULL;
        inBuffers[1].cbBuffer   = 0;
        inBuffers[1].BufferType = SECBUFFER_EMPTY;

        inBuffer.cBuffers       = 2;
        inBuffer.pBuffers       = inBuffers;
        inBuffer.ulVersion      = SECBUFFER_VERSION;

        //
        // Set up the output buffers. These are initialized to NULL
        // so as to make it less likely we'll attempt to free random
        // garbage later.
        //

        outBuffers[0].pvBuffer  = NULL;
        outBuffers[0].BufferType= SECBUFFER_TOKEN;
        outBuffers[0].cbBuffer  = 0;

        outBuffer.cBuffers      = 1;
        outBuffer.pBuffers      = outBuffers;
        outBuffer.ulVersion     = SECBUFFER_VERSION;

        //
        // Call InitializeSecurityContext.
        //

        scRet = g_pSSPI->InitializeSecurityContextA(
                            Creds,
                            Context,
                            NULL,
                            dwSSPIFlags,
                            0,
                            0,
                            &inBuffer,
                            0,
                            NULL,
                            &outBuffer,
                            &dwSSPIOutFlags,
                            &tsExpiry
                        );

        //
        // If InitializeSecurityContext was successful (or if the error was 
        // one of the special extended ones), send the contents of the output
        // buffer to the server.
        //

        if ( scRet == SEC_E_OK                ||
             scRet == SEC_I_CONTINUE_NEEDED   ||
             FAILED(scRet) && (dwSSPIOutFlags & ISC_RET_EXTENDED_ERROR) )
        {
            if ( outBuffers[0].cbBuffer != 0 && outBuffers[0].pvBuffer != NULL )
            {
                cbData = send(Socket,
                              (PCHAR)outBuffers[0].pvBuffer,
                              outBuffers[0].cbBuffer,
                              0);
                if ( cbData == SOCKET_ERROR || cbData == 0 )
                {
                    scRet = SEC_E_INTERNAL_ERROR;
                    logger.logError(loggerId, WSAGetLastError(), "sending data to server (2)\n");
                    g_pSSPI->FreeContextBuffer(outBuffers[0].pvBuffer);
                    deleteSecurityContext(Context);
                    return scRet;
                }

#ifdef DEBUG_PRINT
                logger.logInfo(loggerId, 0, "0x%x bytes of handshake data sent\n", cbData);
#endif
#ifdef DEBUG_PRINT_HEX_DUMP
                PrintHexDump(cbData, outBuffers[0].pvBuffer);
                logger.logInfo(loggerId, 0, "\n");
#endif

                // Free output buffer.
                g_pSSPI->FreeContextBuffer(outBuffers[0].pvBuffer);
                outBuffers[0].pvBuffer = NULL;
            }
        }


        //
        // If InitializeSecurityContext returned SEC_E_INCOMPLETE_MESSAGE,
        // then we need to read more data from the server and try again.
        //

        if ( scRet == SEC_E_INCOMPLETE_MESSAGE )
        {
            continue;
        }


        //
        // If InitializeSecurityContext returned SEC_E_OK, 
        // then the handshake completed successfully.
        //

        if ( scRet == SEC_E_OK )
        {
            //
            // If the "extra" buffer contains data, this is encrypted application
            // protocol layer stuff. It needs to be saved. The application layer
            // will later decrypt it with DecryptMessage.
            //

            logger.logInfo(loggerId, 0, "Handshake was successful\n");

            if ( inBuffers[1].BufferType == SECBUFFER_EXTRA )
            {
                pExtraData->pvBuffer = (PVOID)LocalAlloc(LMEM_FIXED, 
                                                  inBuffers[1].cbBuffer);
                if ( pExtraData->pvBuffer == NULL )
                {
                    scRet = SEC_E_INTERNAL_ERROR;
                    logger.logError(loggerId, scRet, "Out of memory (2)\n");
                    return scRet;
                }

                MoveMemory(pExtraData->pvBuffer,
                           IoBuffer + (cbIoBuffer - inBuffers[1].cbBuffer),
                           inBuffers[1].cbBuffer);

                pExtraData->cbBuffer = inBuffers[1].cbBuffer;
                pExtraData->BufferType = SECBUFFER_TOKEN;

                logger.logInfo(loggerId, 0, "INFO: 0x%x bytes of app data was bundled with handshake data\n",
                    pExtraData->cbBuffer);
            }
            else
            {
                pExtraData->pvBuffer   = NULL;
                pExtraData->cbBuffer   = 0;
                pExtraData->BufferType = SECBUFFER_EMPTY;
            }

            // Bail out to quit
            break;
        }

        // Check for fatal error.
        if ( FAILED(scRet) )
        {
            logger.logError(loggerId, scRet, "returned by InitializeSecurityContext (2)\n");
            break;
        }

        //
        // If InitializeSecurityContext returned SEC_I_INCOMPLETE_CREDENTIALS,
        // then the server just requested client authentication. 
        //

        if ( scRet == SEC_I_INCOMPLETE_CREDENTIALS )
        {
            //
            // Busted. The server has requested client authentication and
            // the credential we supplied didn't contain a client certificate.
            
            // We break
            logger.logError(loggerId, scRet, "The server has requested client authentication and the credential we supplied didn't contain a client certificate.\n");
            break;

            // 
            // This function will read the list of trusted certificate
            // authorities ("issuers") that was received from the server
            // and attempt to find a suitable client certificate that
            // was issued by one of these. If this function is successful, 
            // then we will connect using the new certificate. Otherwise,
            // we will attempt to connect anonymously (using our current
            // credentials).
            //
            
            //GetNewClientCredentials(Creds, Context);

            //// Go around again.
            //fDoRead = FALSE;
            //scRet = SEC_I_CONTINUE_NEEDED;
            //continue;
        }


        //
        // Copy any leftover data from the "extra" buffer, and go around
        // again.
        //

        if ( inBuffers[1].BufferType == SECBUFFER_EXTRA )
        {
            MoveMemory(IoBuffer,
                       IoBuffer + (cbIoBuffer - inBuffers[1].cbBuffer),
                       inBuffers[1].cbBuffer);

            cbIoBuffer = inBuffers[1].cbBuffer;
        }
        else
        {
            cbIoBuffer = 0;
        }
    }

    // Delete the security context in the case of a fatal error.
    if ( FAILED(scRet) )
    {
        logger.logError(loggerId, scRet, "client handshake loop (%s)\n", getSecErrorString(scRet));
        deleteSecurityContext(Context);
    }

    LocalFree(IoBuffer);

    return scRet;
}

LONG
VerifyServerCertificate(
    _In_ PCCERT_CONTEXT Cert,
    _In_ PSTR ServerIp,
    _In_ DWORD CertFlags)
{
    HTTPSPolicyCallbackData polHttps;
    CERT_CHAIN_POLICY_PARA policyPara;
    CERT_CHAIN_POLICY_STATUS policyStatus;
    CERT_CHAIN_PARA chainPara;
    PCCERT_CHAIN_CONTEXT pChainContext = NULL;

    LPSTR rgszUsages[] = {  (CHAR*)szOID_PKIX_KP_SERVER_AUTH,
                            (CHAR*)szOID_SERVER_GATED_CRYPTO,
                            (CHAR*)szOID_SGC_NETSCAPE };
    DWORD cUsages = sizeof(rgszUsages) / sizeof(LPSTR);

    PWSTR pwszServerName = NULL;
    DWORD cchServerName;
    LONG status;

    if ( Cert == NULL )
    {
        status = SEC_E_WRONG_PRINCIPAL;
        goto cleanup;
    }


    //
    // Convert server name to unicode.
    //

    if ( ServerIp == NULL || strlen(ServerIp) == 0 )
    {
        status = SEC_E_WRONG_PRINCIPAL;
        goto cleanup;
    }

    cchServerName = MultiByteToWideChar(CP_ACP, 0, ServerIp, -1, NULL, 0);
    pwszServerName = (PWSTR) LocalAlloc(LMEM_FIXED, cchServerName * sizeof(WCHAR));
    if ( pwszServerName == NULL )
    {
        status = SEC_E_INSUFFICIENT_MEMORY;
        goto cleanup;
    }
    cchServerName = MultiByteToWideChar(CP_ACP, 0, ServerIp, -1, pwszServerName, cchServerName);
    if ( cchServerName == 0 )
    {
        status = SEC_E_WRONG_PRINCIPAL;
        goto cleanup;
    }


    //
    // Build certificate chain.
    //

    ZeroMemory(&chainPara, sizeof(chainPara));
    chainPara.cbSize = sizeof(chainPara);
    chainPara.RequestedUsage.dwType = USAGE_MATCH_TYPE_OR;
    chainPara.RequestedUsage.Usage.cUsageIdentifier = cUsages;
    chainPara.RequestedUsage.Usage.rgpszUsageIdentifier = rgszUsages;

    if ( !CertGetCertificateChain(
                            NULL,
                            Cert,
                            NULL,
                            Cert->hCertStore,
                            &chainPara,
                            0,
                            NULL,
                            &pChainContext) )
    {
        status = GetLastError();
        logger.logError(loggerId, status, "CertGetCertificateChain!\n");
        goto cleanup;
    }


    //
    // Validate certificate chain.
    // 

    ZeroMemory(&polHttps, sizeof(HTTPSPolicyCallbackData));
    polHttps.cbStruct           = sizeof(HTTPSPolicyCallbackData);
    polHttps.dwAuthType         = AUTHTYPE_SERVER;
    polHttps.fdwChecks          = CertFlags;
    polHttps.pwszServerName     = pwszServerName;

    memset(&policyPara, 0, sizeof(policyPara));
    policyPara.cbSize = sizeof(policyPara);
    policyPara.pvExtraPolicyPara = &polHttps;

    memset(&policyStatus, 0, sizeof(policyStatus));
    policyStatus.cbSize = sizeof(policyStatus);

    if ( !CertVerifyCertificateChainPolicy(
                            CERT_CHAIN_POLICY_SSL,
                            pChainContext,
                            &policyPara,
                            &policyStatus) )
    {
        status = GetLastError();
        logger.logError(loggerId, status, "CertVerifyCertificateChainPolicy!\n");
        goto cleanup;
    }

    if ( policyStatus.dwError )
    {
        status = policyStatus.dwError;
        logger.logError(loggerId, status, "%s!\n", GetWinVerifyTrustError(status));
        if ( policyStatus.dwError == CERT_E_UNTRUSTEDROOT )
            logger.logInfo(loggerId, 0, "skipping\n");
        else
            goto cleanup;
    }


    status = SEC_E_OK;

cleanup:

    if(pChainContext)
    {
        CertFreeCertificateChain(pChainContext);
    }

    if(pwszServerName)
    {
        LocalFree(pwszServerName);
    }

    return status;
}

BOOL
SSPINegotiateLoop(
    _In_ SOCKET Socket,
    _Out_ PCtxtHandle Context,
    _In_ PCredHandle phCred,
    _In_ BOOL fDoInitialRead,
    _In_ BOOL NewContext,
    _In_ PBYTE pbIoBuffer,
    _In_ ULONG cbIoBuffer,
    _In_ ULONG cbInitialData
)
{
    TimeStamp tsExpiry;
    SECURITY_STATUS scRet;
    SecBufferDesc inBuffer;
    SecBufferDesc outBuffer;
    SecBuffer inBuffers[2];
    SecBuffer outBuffers[1];
    DWORD cbData = 0;

    BOOL fDoRead;
    BOOL fInitContext = NewContext;

    DWORD dwSSPIFlags, dwSSPIOutFlags;

    fDoRead = fDoInitialRead;
    DWORD cbIoBufferLength = cbIoBuffer;

    dwSSPIFlags =   ASC_REQ_SEQUENCE_DETECT |
                    ASC_REQ_REPLAY_DETECT   |
                    ASC_REQ_CONFIDENTIALITY |
                    ASC_REQ_EXTENDED_ERROR  |
                    ASC_REQ_ALLOCATE_MEMORY |
                    ASC_REQ_STREAM;

    if ( fClientAuth )
    {
        dwSSPIFlags |= ASC_REQ_MUTUAL_AUTH;
    }


    //
    //  set outBuffer for InitializeSecurityContext call
    //

    outBuffer.cBuffers = 1;
    outBuffer.pBuffers = outBuffers;
    outBuffer.ulVersion = SECBUFFER_VERSION;


    scRet = SEC_I_CONTINUE_NEEDED;
    cbIoBuffer = fDoInitialRead ? 0 : cbInitialData;

    while( scRet == SEC_I_CONTINUE_NEEDED ||
           scRet == SEC_E_INCOMPLETE_MESSAGE ||
           scRet == SEC_I_INCOMPLETE_CREDENTIALS) 
    {
        if ( 0 == cbIoBuffer || scRet == SEC_E_INCOMPLETE_MESSAGE )
        {
            if ( cbIoBuffer >= cbIoBufferLength )
            {
                logger.logError(loggerId, SCHAT_ERROR_TLS_NEGOTIATION, "buffer too big\n");
                return FALSE;
            }

            if ( fDoRead )
            {
                cbData = recv(Socket, (PCHAR)(pbIoBuffer+cbIoBuffer), cbIoBufferLength - cbIoBuffer, 0);

                if ( cbData == SOCKET_ERROR || cbData == 0 )
                {
                    logger.logError(loggerId, GetLastError(), "recv failed\n");
                    return FALSE;
                }

                logger.logInfo(loggerId, 0, "\nReceived 0x%x (handshake) bytes from client\n", cbData);

#ifdef DEBUG_PRINT_HEX_DUMP
                PrintHexDump(cbData, pbIoBuffer+cbIoBuffer);
#endif
                cbIoBuffer += cbData;
            }
            else
            {
                fDoRead = TRUE;
            }
        }


        //
        // inBuffers[1] is for getting extra data that
        //  SSPI/SCHANNEL doesn't proccess on this
        //  run around the loop.
        //

        inBuffers[0].pvBuffer = pbIoBuffer;
        inBuffers[0].cbBuffer = cbIoBuffer;
        inBuffers[0].BufferType = SECBUFFER_TOKEN;

        inBuffers[1].pvBuffer = NULL;
        inBuffers[1].cbBuffer = 0;
        inBuffers[1].BufferType = SECBUFFER_EMPTY;

        inBuffer.cBuffers = 2;
        inBuffer.pBuffers = inBuffers;
        inBuffer.ulVersion = SECBUFFER_VERSION;


        //
        // Initialize these so if we fail, pvBuffer contains NULL,
        // so we don't try to free random garbage at the quit
        //

        outBuffers[0].pvBuffer = NULL;
        outBuffers[0].BufferType = SECBUFFER_TOKEN;
        outBuffers[0].cbBuffer = 0;


        scRet = g_pSSPI->AcceptSecurityContext(
                        phCred,
                        (fInitContext?NULL:Context),
                        &inBuffer,
                        dwSSPIFlags,
                        0,
                        (fInitContext?Context:NULL),
                        &outBuffer,
                        &dwSSPIOutFlags,
                        &tsExpiry);

        fInitContext = FALSE;

        if ( scRet == SEC_E_OK ||
             scRet == SEC_I_CONTINUE_NEEDED ||
             (FAILED(scRet) && (0 != (dwSSPIOutFlags & ISC_RET_EXTENDED_ERROR))))
        {
            if  (outBuffers[0].cbBuffer != 0    &&
                 outBuffers[0].pvBuffer != NULL )
            {
                // Send response to server if there is one
                cbData = send(Socket,
                              (PCHAR)outBuffers[0].pvBuffer,
                              outBuffers[0].cbBuffer,
                              0);

                logger.logInfo(loggerId, 0, "\nSend 0x%x handshake bytes to client\n", outBuffers[0].cbBuffer);

#ifdef DEBUG_PRINT_HEX_DUMP
                PrintHexDump(outBuffers[0].cbBuffer, outBuffers[0].pvBuffer);
#endif

                g_pSSPI->FreeContextBuffer(outBuffers[0].pvBuffer);
                outBuffers[0].pvBuffer = NULL;
            }
        }

        if ( scRet == SEC_E_OK )
        {
            if ( inBuffers[1].BufferType == SECBUFFER_EXTRA )
            {
                memcpy(pbIoBuffer,
                       (LPBYTE) (pbIoBuffer + (cbIoBuffer - inBuffers[1].cbBuffer)),
                       inBuffers[1].cbBuffer);
                cbIoBuffer = inBuffers[1].cbBuffer;
            }
            else
            {
                cbIoBuffer = 0;
            }

            //if ( fClientAuth )
            //{
            //    // Display info about cert...
            //}

            return TRUE;
        }
        else if (FAILED(scRet) && (scRet != SEC_E_INCOMPLETE_MESSAGE))
        {
            logger.logError(loggerId, scRet, "Accept Security Context failed : %s\n", getSecErrorString(scRet));
            return FALSE;
        }

        if ( scRet != SEC_E_INCOMPLETE_MESSAGE &&
             scRet != SEC_I_INCOMPLETE_CREDENTIALS )
        {
            if ( inBuffers[1].BufferType == SECBUFFER_EXTRA )
            {
                memcpy(pbIoBuffer,
                       (LPBYTE) (pbIoBuffer + (cbIoBuffer - inBuffers[1].cbBuffer)),
                        inBuffers[1].cbBuffer);
                cbIoBuffer = inBuffers[1].cbBuffer;
            }
            else
            {
                // prepare for next receive
                cbIoBuffer = 0;
            }
        }
    }

    return FALSE;
}

INT
CheckConnectionInfo(
    _In_ CtxtHandle *Context,
    _In_ PSecurityFunctionTable SSPI
)
{
    SECURITY_STATUS status;
    SecPkgContext_ConnectionInfo ConnectionInfo;

    status = SSPI->QueryContextAttributes(
        Context,
        SECPKG_ATTR_CONNECTION_INFO,
        (PVOID)&ConnectionInfo
    );
    if ( status != SEC_E_OK )
    {
        logger.logError(loggerId, status, "querying connection info\n");
        return -1;
    }

    if ( !(ConnectionInfo.dwProtocol & SP_PROT_TLS1_2) &&
         !(ConnectionInfo.dwProtocol & SP_PROT_TLS1_3) )
    {
        return -1;
    }

    return 0;
}

INT
readStreamEncryptionProperties(
    _Out_ SecPkgContext_StreamSizes* Sizes,
    _In_ CtxtHandle *Context
)
{
    int scRet = g_pSSPI->QueryContextAttributes(Context,
                                   SECPKG_ATTR_STREAM_SIZES,
                                   Sizes);
    if ( scRet != SEC_E_OK )
    {
        logger.logError(loggerId, scRet, "reading SECPKG_ATTR_STREAM_SIZES\n");
        return scRet;
    }
#ifdef DEBUG_PRINT
    logger.logInfo(loggerId, 0, "Sizes:\n - Header: 0x%x\n - Trailer: 0x%x\n - MaxMessage: 0x%x\n - Buffers: 0x%x\n - BlockSize: 0x%x\n",
        Sizes->cbHeader,
        Sizes->cbTrailer,
        Sizes->cbMaximumMessage,
        Sizes->cBuffers,
        Sizes->cbBlockSize
    );
#endif
    return 0;
}

//
// Allocate a working buffer. The plaintext sent to EncryptMessage
// should never be more than 'pSizes.cbMaximumMessage', so a buffer 
// size of this plus the header and trailer sizes should be safe enough.
// 
INT
allocateBuffer(
    _In_ SecPkgContext_StreamSizes* pSizes,
    _Out_ PBYTE* pbBuffer,
    _Out_ ULONG* cbBuffer
)
{
    *cbBuffer = pSizes->cbHeader + 
                pSizes->cbMaximumMessage +
                pSizes->cbTrailer;
    
    *pbBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, *cbBuffer);
    if ( *pbBuffer == NULL )
    {
        logger.logError(loggerId, (ULONG)SEC_E_INTERNAL_ERROR, "Out of memory (2)\n");
        *cbBuffer = 0;
        return SEC_E_INTERNAL_ERROR;
    }

    return 0;
}

SECURITY_STATUS sendSChannelData(
    _In_ PUCHAR pbMessage,
    _In_ ULONG cbMessage, 
    _In_ SOCKET Socket,
    _In_ CtxtHandle *Context,
    _In_ SecPkgContext_StreamSizes* Sizes,
    _In_ PBYTE pbIoBuffer,
    _In_ ULONG cbIoBuffer
)
{
    SECURITY_STATUS scRet;
    SecBufferDesc encMessage;
    SecBuffer buffers[4];

    //DWORD cbData;

    UNREFERENCED_PARAMETER(cbIoBuffer);

    // Build the message offset into the data buffer by "header size" bytes. 
    // This enables Schannel to perform the encryption in place, which is a significant performance win.

      
#if defined(DEBUG_PRINT_HEX_DUMP) && defined(DEBUG_PRINT_MESSAGE)
    logger.logInfo(loggerId, 0, "pbMessage (0x%x):\n", cbMessage);
    PrintHexDump(cbMessage, pbMessage);
    logger.logInfo(loggerId, 0, "\n");
#endif

    //
    // Encrypt the HTTP request.
    //

    buffers[0].pvBuffer = pbIoBuffer;
    buffers[0].cbBuffer = Sizes->cbHeader;
    buffers[0].BufferType = SECBUFFER_STREAM_HEADER;

    buffers[1].pvBuffer = pbMessage;
    buffers[1].cbBuffer = cbMessage;
    buffers[1].BufferType = SECBUFFER_DATA;

    buffers[2].pvBuffer = pbMessage + cbMessage;
    buffers[2].cbBuffer = Sizes->cbTrailer;
    buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;

    buffers[3].BufferType = SECBUFFER_EMPTY;

    encMessage.ulVersion = SECBUFFER_VERSION;
    encMessage.cBuffers = 4;
    encMessage.pBuffers = buffers;
     
    scRet = g_pSSPI->EncryptMessage(
                        Context, 
                        0, 
                        &encMessage, 
                        0
                    );

    if ( FAILED(scRet) )
    {
        logger.logError(loggerId, scRet, "EncryptMessage failed (%s)\n", getSecErrorString(scRet));
        return scRet;
    }


    // 
    // Send the encrypted data to the server.
    //
    ULONG total = buffers[0].cbBuffer + buffers[1].cbBuffer + buffers[2].cbBuffer;
    ULONG sent  = 0;
    while ( sent < total )
    {
        int n = send(Socket, (PCHAR)(pbIoBuffer + sent), total - sent, 0);
        if ( n == SOCKET_ERROR )
        {
            scRet = WSAGetLastError();
            if ( scRet == WSAEWOULDBLOCK )
            {
                Sleep(SEND_LOOP_SLEEP);
                continue;                 // retry the REMAINING bytes — do NOT re-encrypt
            }
            logger.logError(loggerId, scRet, "Sending data to server (3)\n");
            return scRet;
        }
        if ( n == 0 )                     // peer closed
            return SEC_E_INTERNAL_ERROR;
        sent += (ULONG)n;
    }

    //cbData = send(Socket,
    //              (PCHAR)pbIoBuffer,
    //              Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer,
    //              0);
    //if ( cbData == SOCKET_ERROR || cbData == 0 )
    //{
    //    //deleteSecurityContext(Context);
    //
    //    scRet = WSAGetLastError();
    //    logger.logError(loggerId, scRet, "Sending data to server (3)\n");
    //    if ( scRet == WSAEWOULDBLOCK || scRet == 0 )
    //    {
    //        logger.logInfo(loggerId, 0, " retry sending\n");
    //        Sleep(SEND_LOOP_SLEEP);
    //        return sendSChannelData(
    //                    pbMessage,
    //                    cbMessage, 
    //                    Socket,
    //                    Context,
    //                    pSizes,
    //                    pbIoBuffer,
    //                    cbIoBuffer
    //                );
    //    }
    //    else
    //    {
    //        logger.logInfo(loggerId, 0, " break\n");
    //        return scRet;
    //    }
    //}

//#ifdef DEBUG_PRINT
//    logger.logInfo(loggerId, 0, "0x%x bytes of application data sent\n", cbData);
//#endif
//#ifdef DEBUG_PRINT_HEX_DUMP
//    PrintHexDump(cbData, pbIoBuffer);
//    logger.logInfo(loggerId, 0, "\n");
//#endif
    
    return SEC_E_OK;
}

SECURITY_STATUS
receiveSChannelData(
    _In_ SOCKET Socket,
    _In_ PCredHandle ServerCreds,
    _In_ PCredHandle ClientCreds,
    _In_ PCtxtHandle Context,
    _In_ SecPkgContext_StreamSizes* Sizes,
    _Inout_ PBYTE pbIoBuffer,
    _In_ ULONG cbIoBuffer,
    _In_ ULONG Type,
    _In_ BOOL* Running
)
{
    SECURITY_STATUS scRet = SEC_E_OK;
    int msgRet = 0;
    SecBufferDesc message;
    SecBuffer buffers[4];
    SecBuffer *dataBuffer;
    SecBuffer *pExtraBuffer;
    SecBuffer hsExtraBuffer;

    DWORD cbIoBufferLength = cbIoBuffer;

    DWORD cbData;
    INT i;

    UNREFERENCED_PARAMETER(Sizes);
    
#ifdef DEBUG_PRINT
    logger.logInfo(loggerId, 0, "receiveSChannelData\n");
#endif

    cbIoBuffer = 0;

    message.ulVersion = SECBUFFER_VERSION;
    message.cBuffers = 4;
    message.pBuffers = buffers;

    while ( *Running )
    {
        // Read some data.
        if ( cbIoBuffer == 0 || scRet == SEC_E_INCOMPLETE_MESSAGE )
        {
            cbData = recv(Socket, 
                          (PCHAR)(pbIoBuffer + cbIoBuffer), 
                          cbIoBufferLength - cbIoBuffer, 
                          0);

            if ( cbData == SOCKET_ERROR )
            {
                cbData = WSAGetLastError();
                // get unblocking message polling some rest
                if ( cbData == WSAEWOULDBLOCK )
                {
                    Sleep(RECEIVE_LOOP_SLEEP);
                    continue;
                }
                else
                {
                    logger.logError(loggerId, cbData, "recv data error\n");
                    scRet = SEC_E_INTERNAL_ERROR;
                    break;
                }
            }
            else if ( cbData == 0 )
            {
                // Server disconnected.
                if ( cbIoBuffer )
                {
                    scRet = SEC_E_INTERNAL_ERROR;
                    logger.logError(loggerId, scRet, "Unexpected Disconnection while receiving\n");
                    break;
                }
                else
                {
                    logger.logInfo(loggerId, 0, "Received 0 bytes\n");
                    break;
                }
            }
            else
            {
#ifdef DEBUG_PRINT
                logger.logInfo(loggerId, 0, "0x%x bytes of (encrypted) application data received\n", cbData);
#endif
#ifdef DEBUG_PRINT_HEX_DUMP
                PrintHexDump(cbData, pbIoBuffer + cbIoBuffer);
                logger.logInfo(loggerId, 0, "\n");
#endif

                cbIoBuffer += cbData;
            }
        }

        // 
        // Attempt to decrypt the received data.
        //

        buffers[0].pvBuffer = pbIoBuffer;
        buffers[0].cbBuffer = cbIoBuffer;
        buffers[0].BufferType = SECBUFFER_DATA;

        buffers[1].BufferType = SECBUFFER_EMPTY;
        buffers[2].BufferType = SECBUFFER_EMPTY;
        buffers[3].BufferType = SECBUFFER_EMPTY;

        scRet = g_pSSPI->DecryptMessage(Context, &message, 0, NULL);

        if ( scRet == SEC_E_INCOMPLETE_MESSAGE )
        {
            // The input buffer contains only a fragment of an
            // encrypted record. Loop around and read some more
            // data.
            continue;
        }

        // remote signalled end of session
        if ( scRet == SEC_I_CONTEXT_EXPIRED )
        {
            logger.logInfo(loggerId, 0, "SEC_I_CONTEXT_EXPIRED\n");
            break;
        }
        if ( scRet != SEC_E_OK && 
             scRet != SEC_I_RENEGOTIATE )
        {
            logger.logError(loggerId, scRet, "DecryptMessage failed (%s)\n", getSecErrorString(scRet));
            break;
        }

        // Locate data and (optional) extra buffers.
        dataBuffer  = NULL;
        pExtraBuffer = NULL;
        for ( i = 0; i < 4; i++ )
        {

            if ( dataBuffer == NULL && buffers[i].BufferType == SECBUFFER_DATA )
            {
                dataBuffer = &buffers[i];
            }
            if ( pExtraBuffer == NULL && buffers[i].BufferType == SECBUFFER_EXTRA )
            {
                pExtraBuffer = &buffers[i];
            }
        }

        // Process the decrypted data.
        if ( dataBuffer && dataBuffer->cbBuffer > 0 )
        {
#ifdef DEBUG_PRINT_MESSAGE
            logger.logInfo(loggerId, 0, "Decrypted data: 0x%x bytes\n", dataBuffer->cbBuffer);
#endif
#if defined(DEBUG_PRINT_MESSAGE) && defined(DEBUG_PRINT_HEX_DUMP)
            PrintHexDump(dataBuffer->cbBuffer, dataBuffer->pvBuffer);
            logger.logInfo(loggerId, 0, "\n");
#endif
            
            msgRet = handleMessage(
                        dataBuffer->pvBuffer, 
                        dataBuffer->cbBuffer,
                        Sizes,
                        Type,
                        Running
                    );
            if ( msgRet != 0 || !(*Running) )
            {
                // pbIoBuffer may be invalid now
                *Running = false;
                break;
            }
        }

        // Move any "extra" data to the input buffer.
        if ( pExtraBuffer )
        {
            MoveMemory(pbIoBuffer, pExtraBuffer->pvBuffer, pExtraBuffer->cbBuffer);
            cbIoBuffer = pExtraBuffer->cbBuffer;
        }
        else
        {
            cbIoBuffer = 0;
        }

        if ( scRet == SEC_I_RENEGOTIATE )
        {
            if ( Type == ENGINE_TYPE_CLIENT )
            {
                // The server wants to perform another handshake
                // sequence.

                logger.logInfo(loggerId, 0, "Server requested renegotiate!\n");

                scRet = ClientHandshakeLoop(Socket, 
                                            ClientCreds, 
                                            Context, 
                                            FALSE, 
                                            &hsExtraBuffer);
                if ( scRet != SEC_E_OK )
                {
                    break;
                }

                // Move any "extra" data to the input buffer.
                if ( hsExtraBuffer.pvBuffer )
                {
                    MoveMemory(pbIoBuffer, hsExtraBuffer.pvBuffer, hsExtraBuffer.cbBuffer);
                    cbIoBuffer = hsExtraBuffer.cbBuffer;
                }
                else
                {
                    cbIoBuffer = 0;
                    continue;
                }
            }
            else
            {
                // The client  wants to perform another handshake sequence.
                logger.logInfo(loggerId, 0, "Client requested renegotiate!\n");

                scRet = !SSPINegotiateLoop(
                            Socket, 
                            Context, 
                            ServerCreds,
                            /*fDoInitialRead=*/FALSE,
                            /*NewContext=*/FALSE,
                            pbIoBuffer, 
                            cbIoBufferLength,
                            cbIoBuffer
                        );
                if ( !scRet )
                {
                    scRet = SEC_E_INTERNAL_ERROR;
                    break;
                }

                cbIoBuffer = 0;
                continue;
            }
        }

        Sleep(RECEIVE_LOOP_SLEEP);
    }

//clean:
    //;

    return (scRet==0) ? msgRet : scRet;
}

LONG
Disconnect(
    _Inout_ SOCKET* Socket, 
    _In_ PCredHandle Creds,
    _Inout_ CtxtHandle *Context,
    _In_ ULONG Type
)
{
    DWORD type;
    PBYTE pbMessage;
    DWORD cbMessage;
    DWORD cbData;

    SecBufferDesc outBuffer;
    SecBuffer outBuffers[1];
    DWORD sspiFlags;
    DWORD sspiOutFlags;
    TimeStamp expiry;
    DWORD status = 0;
    
    logger.logInfo(loggerId, 0, "Disconnect()\n");
    
    //
    // Notify schannel that we are about to close the connection.
    //
    
    type = SCHANNEL_SHUTDOWN;
    
    if ( *Socket == INVALID_SOCKET )
        goto cleanup;
    if ( Creds == NULL || (Creds->dwLower == 0 && Creds->dwUpper == 0) )
        goto cleanup;
    if ( Context == NULL || (Context->dwLower == 0 && Context->dwUpper == 0) )
        goto cleanup;
    
    outBuffers[0].pvBuffer = &type;
    outBuffers[0].BufferType = SECBUFFER_TOKEN;
    outBuffers[0].cbBuffer = sizeof(type);
    
    outBuffer.cBuffers = 1;
    outBuffer.pBuffers = outBuffers;
    outBuffer.ulVersion = SECBUFFER_VERSION;
    
    status = g_pSSPI->ApplyControlToken(Context, &outBuffer);
    
    if ( FAILED(status) ) 
    {
        logger.logError(loggerId, status, "ApplyControlToken\n");
        goto cleanup;
    }
    
    //
    // Build an SSL close notify message.
    //
    
    sspiFlags =   ASC_REQ_SEQUENCE_DETECT     |
                    ASC_REQ_REPLAY_DETECT       |
                    ASC_REQ_CONFIDENTIALITY     |
                    ASC_REQ_EXTENDED_ERROR      |
                    ASC_REQ_ALLOCATE_MEMORY     |
                    ASC_REQ_STREAM;
    
    outBuffers[0].pvBuffer   = NULL;
    outBuffers[0].BufferType = SECBUFFER_TOKEN;
    outBuffers[0].cbBuffer   = 0;

    outBuffer.cBuffers  = 1;
    outBuffer.pBuffers  = outBuffers;
    outBuffer.ulVersion = SECBUFFER_VERSION;
    
    if ( Type == ENGINE_TYPE_SERVER )
    {
        status = g_pSSPI->AcceptSecurityContext(
                        Creds,
                        Context,
                        NULL,
                        sspiFlags,
                        0,
                        NULL,
                        &outBuffer,
                        &sspiOutFlags,
                        &expiry);

        if ( FAILED(status) ) 
        {
            logger.logError(loggerId, status, "AcceptSecurityContext\n");
            goto cleanup;
        }
    }
    else if ( Type == ENGINE_TYPE_CLIENT )
    {
        status = g_pSSPI->InitializeSecurityContextA(
                        Creds,
                        Context,
                        NULL,
                        sspiFlags,
                        0,
                        0,
                        NULL,
                        0,
                        Context,
                        &outBuffer,
                        &sspiOutFlags,
                        &expiry);
    
        if ( FAILED(status) ) 
        {
            logger.logError(loggerId, status, "InitializeSecurityContext\n");
            goto cleanup;
        }
    }
    
    pbMessage = (PBYTE)outBuffers[0].pvBuffer;
    cbMessage = outBuffers[0].cbBuffer;
    
    
    //
    // Send the close notify message to the client.
    //
    
    if ( pbMessage != NULL && cbMessage != 0 )
    {
        cbData = send(*Socket, (PCHAR)pbMessage, cbMessage, 0);
        if ( cbData == SOCKET_ERROR || cbData == 0 )
        {
            status = WSAGetLastError();
            logger.logError(loggerId, status, "Sending close notify : %s\n", getWSAErrorString(status));
            goto cleanup;
        }
        
        logger.logInfo(loggerId, 0, "Sending Close Notify\n");
#ifdef DEBUG_PRINT
        logger.logInfo(loggerId, 0, "\n0x%x bytes of handshake data sent\n", cbData);
#endif
#ifdef DEBUG_PRINT_HEX_DUMP
        PrintHexDump(cbData, pbMessage);
        logger.logInfo(loggerId, 0, "\n");
#endif
        // Free output buffer.
        g_pSSPI->FreeContextBuffer(pbMessage);
    }
    
cleanup:
    deleteSecurityContext(Context);
    if ( *Socket != INVALID_SOCKET )
        closesocket(*Socket);
    *Socket = INVALID_SOCKET;

    return status;
}

LONG
VerifyClientCertificate(
    _In_ PCCERT_CONTEXT Cert,
    _In_ DWORD CertFlags
)
{
    HTTPSPolicyCallbackData polHttps;
    CERT_CHAIN_POLICY_PARA policyPara;
    CERT_CHAIN_POLICY_STATUS policyStatus;
    CERT_CHAIN_PARA chainPara;
    PCCERT_CHAIN_CONTEXT pChainContext = NULL;
    LPSTR pszUsage;

    DWORD status;

    if ( Cert == NULL )
    {
        return SEC_E_WRONG_PRINCIPAL;
    }


    //
    // Build certificate chain.
    //

    pszUsage = (CHAR*)szOID_PKIX_KP_CLIENT_AUTH;

    ZeroMemory(&chainPara, sizeof(chainPara));
    chainPara.cbSize = sizeof(chainPara);
    chainPara.RequestedUsage.dwType = USAGE_MATCH_TYPE_OR;
    chainPara.RequestedUsage.Usage.cUsageIdentifier = 1;
    chainPara.RequestedUsage.Usage.rgpszUsageIdentifier = &pszUsage;

    if ( !CertGetCertificateChain(
                            NULL,
                            Cert,
                            NULL,
                            Cert->hCertStore,
                            &chainPara,
                            0,
                            NULL,
                            &pChainContext) )
    {
        status = GetLastError();
        logger.logError(loggerId, status, "returned by CertGetCertificateChain!\n");
        goto cleanup;
    }


    //
    // Validate certificate chain.
    // 

    ZeroMemory(&polHttps, sizeof(HTTPSPolicyCallbackData));
    polHttps.cbStruct = sizeof(HTTPSPolicyCallbackData);
    polHttps.dwAuthType = AUTHTYPE_CLIENT;
    polHttps.fdwChecks = CertFlags;
    polHttps.pwszServerName = NULL;

    memset(&policyPara, 0, sizeof(policyPara));
    policyPara.cbSize = sizeof(policyPara);
    policyPara.pvExtraPolicyPara = &polHttps;

    memset(&policyStatus, 0, sizeof(policyStatus));
    policyStatus.cbSize = sizeof(policyStatus);

    if ( !CertVerifyCertificateChainPolicy(
                            CERT_CHAIN_POLICY_SSL,
                            pChainContext,
                            &policyPara,
                            &policyStatus) )
    {
        status = GetLastError();
        logger.logError(loggerId, status, "returned by CertVerifyCertificateChainPolicy!\n");
        goto cleanup;
    }

    if ( policyStatus.dwError )
    {
        status = policyStatus.dwError;
        logger.logError(loggerId, status, "%s!\n", GetWinVerifyTrustError(status));
        if ( policyStatus.dwError == CERT_E_UNTRUSTEDROOT )
            logger.logInfo(loggerId, 0, "skipping\n");
        else
            goto cleanup;
    }

    status = SEC_E_OK;

cleanup:

    if ( pChainContext )
    {
        CertFreeCertificateChain(pChainContext);
    }

    return status;
}

void SChannel_clean(
    _Inout_ PCtxtHandle Context,
    _Inout_ PCredHandle ClientCreds,
    _Inout_ PCredHandle ServerCreds,
    _Inout_ HCERTSTORE* CertStore
)
{
    deleteSecurityContext(Context);
    
    deleteCreds(ClientCreds);

    deleteCreds(ServerCreds);

    if ( *CertStore )
    {
        CertCloseStore(*CertStore, 0);
        *CertStore = NULL;
    }
}

void deleteCreds(
    _Inout_ PCredHandle Creds
)
{
    if ( Creds && Creds->dwLower != 0 && Creds->dwUpper != 0 )
    {
        g_pSSPI->FreeCredentialsHandle(Creds);
        Creds->dwLower = 0;
        Creds->dwUpper = 0;
    }
}

void deleteSecurityContext(
    _Inout_ CtxtHandle *Context
)
{
    if ( Context != NULL && Context->dwLower != 0 && Context->dwUpper != 0 )
    {
        g_pSSPI->DeleteSecurityContext(Context);
        Context->dwLower = 0;
        Context->dwUpper = 0;
    }
}

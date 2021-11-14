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
    _In_ PCredHandle phCreds,
    _Inout_ CtxtHandle *phContext,
    _In_ BOOL fDoInitialRead,
    _Out_ SecBuffer *pExtraData
);



BOOL
initSecurityInterface()
{
    g_pSSPI = InitSecurityInterfaceA();

    if ( g_pSSPI == NULL )
    {
        fprintf(out, "ERROR (0x%x): reading security interface.\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

SECURITY_STATUS
CreateCredentials(
    _In_ LPSTR certId,
    _Out_ PCredHandle phCreds,
    _In_ ULONG credFlags,
    _In_ ULONG fCredentialUse
)
{
    TimeStamp tsExpiry;
    SECURITY_STATUS Status = SEC_E_OK;
    PCCERT_CONTEXT pCertContext = NULL;
    SCH_CREDENTIALS SchCreds;
    
    if ( certId == NULL )
    {
        fprintf(out, "ERROR: Missing certificate identifier\n");
        return SEC_E_NO_CREDENTIALS;
    }

    if ( hMyCertStore == NULL )
    {
        hMyCertStore = CertOpenSystemStoreA(0, "MY");

        if ( !hMyCertStore )
        {
            Status = GetLastError();
            fprintf(out, "ERROR (0x%x): CertOpenSystemStore\n", Status);
            return Status;
        }
    }

    uint8_t hash_data[SHA1_BYTES_LN];
    uint8_t* hash_ptr = hash_data; // passing &hash_data to function does not work
    Status = parsePlainBytes(certId, &hash_ptr, SHA1_BYTES_LN);
    if ( Status != 0 )
    {
        fprintf(out, "ERROR (0x%x): parsePlainBytes\n", Status);
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
        fprintf(out, "ERROR (0x%x): CertFindCertificateInStore\n", GetLastError());
        return SEC_E_NO_CREDENTIALS;
    }

    // throws error, if tls 1_2 is disabled
    //TLS_PARAMETERS tlsParams;
    //ZeroMemory(&tlsParams, sizeof(tlsParams));
    //tlsParams.grbitDisabledProtocols = SP_PROT_TLS1_0 | 
    //                                   SP_PROT_TLS1_1 |
    //                                   SP_PROT_TLS1_2;

    ZeroMemory(&SchCreds, sizeof(SchCreds));
    SchCreds.dwVersion  = SCH_CREDENTIALS_VERSION;
    SchCreds.cCreds = 1;
    SchCreds.paCred = &pCertContext;
    SchCreds.dwFlags |= credFlags;
    //SchCreds.cTlsParameters = 1;
    //SchCreds.pTlsParameters = &tlsParams;
    SchCreds.dwSessionLifespan = 10; // 0 for default of 36000000 milliseconds (ten hours)

    // Create an SSPI credential.
    Status = g_pSSPI->AcquireCredentialsHandleA(
                        NULL,                   // Name of principal    
                        //TLS1SP_NAME_A,    // Name of package
                        //SCHANNEL_NAME_A,    // Name of package
                        //(CHAR*)DEFAULT_TLS_SSP_NAME_A,    // Name of package
                        (CHAR*)UNISP_NAME_A,    // Name of package
                        fCredentialUse,   // Flags indicating use
                        NULL,                   // Pointer to logon ID
                        &SchCreds,          // Package specific data
                        NULL,                   // Pointer to GetKey() func
                        NULL,                   // Value to pass to GetKey()
                        phCreds,                // (out) Cred Handle
                        &tsExpiry);             // (out) Lifetime (optional)
    if ( Status != SEC_E_OK )
    {
        fprintf(out, "ERROR (0x%x): %s returned by AcquireCredentialsHandle\n", Status, getSecErrorString(Status));
        goto cleanup;
    }

    SYSTEMTIME sts;
    FileTimeToSystemTime(
        (FILETIME*)&tsExpiry,
        &sts
    );
    fprintf(out, "cred expire: %02d.%02d.%04d %02d:%02d:%02d\n\n", 
        sts.wDay, sts.wMonth, sts.wYear, sts.wHour, sts.wMinute, sts.wSecond);

    //printCert(pCertContext, out);

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

    return Status;
}

SECURITY_STATUS
PerformClientHandshake(
    _In_ SOCKET Socket,
    _In_ PCredHandle phCreds,
    _In_ LPSTR ServerIp,
    _Out_ CtxtHandle *phContext,
    _Out_ SecBuffer *pExtraData
)
{
    SecBufferDesc OutBuffer;
    SecBuffer OutBuffers[1];
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

    OutBuffers[0].pvBuffer = NULL;
    OutBuffers[0].BufferType = SECBUFFER_TOKEN;
    OutBuffers[0].cbBuffer = 0;

    OutBuffer.cBuffers = 1;
    OutBuffer.pBuffers = OutBuffers;
    OutBuffer.ulVersion = SECBUFFER_VERSION;

    scRet = g_pSSPI->InitializeSecurityContextA(
                    phCreds,
                    NULL,
                    ServerIp,
                    dwSSPIFlags,
                    0,
                    0,
                    NULL,
                    0,
                    phContext,
                    &OutBuffer,
                    &dwSSPIOutFlags,
                    &tsExpiry);

    if ( scRet != SEC_I_CONTINUE_NEEDED )
    {
        fprintf(out, "ERROR (0x%x): InitializeSecurityContext (1)\n", scRet);
        return scRet;
    }

    // Send response to server if there is one.
    if ( OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != NULL )
    {
        cbData = send(Socket,
                      (PCHAR)OutBuffers[0].pvBuffer,
                      OutBuffers[0].cbBuffer,
                      0);
        if ( cbData == SOCKET_ERROR || cbData == 0 )
        {
            fprintf(out, "ERROR (0x%x): Sending hello data to server (1)\n", WSAGetLastError());
            g_pSSPI->FreeContextBuffer(OutBuffers[0].pvBuffer);
            deleteSecurityContext(phContext);
            return SEC_E_INTERNAL_ERROR;
        }

#ifdef DEBUG_PRINT
        fprintf(out, "0x%x bytes of handshake data sent\n", cbData);
#endif
#ifdef DEBUG_PRINT_HEX_DUMP
        PrintHexDump(cbData, OutBuffers[0].pvBuffer, out);
        fprintf(out, "\n");
#endif

        // Free output buffer.
        g_pSSPI->FreeContextBuffer(OutBuffers[0].pvBuffer);
        OutBuffers[0].pvBuffer = NULL;
    }


    return ClientHandshakeLoop(Socket, phCreds, phContext, TRUE, pExtraData);
}

static
SECURITY_STATUS
ClientHandshakeLoop(
    _In_ SOCKET Socket,
    _In_ PCredHandle phCreds,
    _Inout_ CtxtHandle *phContext,
    _In_ BOOL fDoInitialRead,
    _Out_ SecBuffer *pExtraData
)
{
    SecBufferDesc InBuffer;
    SecBuffer InBuffers[2];
    SecBufferDesc OutBuffer;
    SecBuffer OutBuffers[1];
    DWORD dwSSPIFlags;
    DWORD dwSSPIOutFlags;
    TimeStamp tsExpiry;
    SECURITY_STATUS scRet;
    DWORD cbData;

    PUCHAR IoBuffer;
    DWORD cbIoBuffer;
    BOOL fDoRead;


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
        fprintf(out, "ERROR: Out of memory (1)\n");
        return SEC_E_INTERNAL_ERROR;
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
                    fprintf(out, "ERROR (0x%x): reading data from server\n", WSAGetLastError());
                    scRet = WSAGetLastError();
                    break;
                }
                else if ( cbData == 0 )
                {
                    fprintf(out, "Server unexpectedly disconnected\n");
                    scRet = WSAECONNRESET;
                    break;
                }

#ifdef DEBUG_PRINT
                fprintf(out, "0x%x bytes of handshake data received\n", cbData);
#endif
#ifdef DEBUG_PRINT_HEX_DUMP
                PrintHexDump(cbData, IoBuffer + cbIoBuffer, out);
                fprintf(out, "\n");
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

        InBuffers[0].pvBuffer   = IoBuffer;
        InBuffers[0].cbBuffer   = cbIoBuffer;
        InBuffers[0].BufferType = SECBUFFER_TOKEN;

        InBuffers[1].pvBuffer   = NULL;
        InBuffers[1].cbBuffer   = 0;
        InBuffers[1].BufferType = SECBUFFER_EMPTY;

        InBuffer.cBuffers       = 2;
        InBuffer.pBuffers       = InBuffers;
        InBuffer.ulVersion      = SECBUFFER_VERSION;

        //
        // Set up the output buffers. These are initialized to NULL
        // so as to make it less likely we'll attempt to free random
        // garbage later.
        //

        OutBuffers[0].pvBuffer  = NULL;
        OutBuffers[0].BufferType= SECBUFFER_TOKEN;
        OutBuffers[0].cbBuffer  = 0;

        OutBuffer.cBuffers      = 1;
        OutBuffer.pBuffers      = OutBuffers;
        OutBuffer.ulVersion     = SECBUFFER_VERSION;

        //
        // Call InitializeSecurityContext.
        //

        scRet = g_pSSPI->InitializeSecurityContextA(
                            phCreds,
                            phContext,
                            NULL,
                            dwSSPIFlags,
                            0,
                            0,
                            &InBuffer,
                            0,
                            NULL,
                            &OutBuffer,
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
            if ( OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != NULL )
            {
                cbData = send(Socket,
                              (PCHAR)OutBuffers[0].pvBuffer,
                              OutBuffers[0].cbBuffer,
                              0);
                if ( cbData == SOCKET_ERROR || cbData == 0 )
                {
                    fprintf(out, "ERROR (0x%x): sending data to server (2)\n", WSAGetLastError());
                    g_pSSPI->FreeContextBuffer(OutBuffers[0].pvBuffer);
                    deleteSecurityContext(phContext);
                    return SEC_E_INTERNAL_ERROR;
                }

#ifdef DEBUG_PRINT
                fprintf(out, "0x%x bytes of handshake data sent\n", cbData);
#endif
#ifdef DEBUG_PRINT_HEX_DUMP
                PrintHexDump(cbData, OutBuffers[0].pvBuffer, out);
                fprintf(out, "\n");
#endif

                // Free output buffer.
                g_pSSPI->FreeContextBuffer(OutBuffers[0].pvBuffer);
                OutBuffers[0].pvBuffer = NULL;
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

            fprintf(out, "Handshake was successful\n");

            if ( InBuffers[1].BufferType == SECBUFFER_EXTRA )
            {
                pExtraData->pvBuffer = (PVOID)LocalAlloc(LMEM_FIXED, 
                                                  InBuffers[1].cbBuffer);
                if ( pExtraData->pvBuffer == NULL )
                {
                    fprintf(out, "ERROR: Out of memory (2)\n");
                    return SEC_E_INTERNAL_ERROR;
                }

                MoveMemory(pExtraData->pvBuffer,
                           IoBuffer + (cbIoBuffer - InBuffers[1].cbBuffer),
                           InBuffers[1].cbBuffer);

                pExtraData->cbBuffer = InBuffers[1].cbBuffer;
                pExtraData->BufferType = SECBUFFER_TOKEN;

                fprintf(out, "INFO: 0x%x bytes of app data was bundled with handshake data\n",
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
            fprintf(out, "ERROR (0x%x): returned by InitializeSecurityContext (2)\n", scRet);
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
            fprintf(out, 
                "ERROR (0x%x): The server has requested client authentication and the credential we supplied didn't contain a client certificate.\n", 
                SEC_I_INCOMPLETE_CREDENTIALS);
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
            
            //GetNewClientCredentials(phCreds, phContext);

            //// Go around again.
            //fDoRead = FALSE;
            //scRet = SEC_I_CONTINUE_NEEDED;
            //continue;
        }


        //
        // Copy any leftover data from the "extra" buffer, and go around
        // again.
        //

        if ( InBuffers[1].BufferType == SECBUFFER_EXTRA )
        {
            MoveMemory(IoBuffer,
                       IoBuffer + (cbIoBuffer - InBuffers[1].cbBuffer),
                       InBuffers[1].cbBuffer);

            cbIoBuffer = InBuffers[1].cbBuffer;
        }
        else
        {
            cbIoBuffer = 0;
        }
    }

    // Delete the security context in the case of a fatal error.
    if ( FAILED(scRet) )
    {
        fprintf(out, "ERROR (0x%x): client handshake loop (%s)\n", scRet, getSecErrorString(scRet));
        deleteSecurityContext(phContext);
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
    CERT_CHAIN_POLICY_PARA PolicyPara;
    CERT_CHAIN_POLICY_STATUS PolicyStatus;
    CERT_CHAIN_PARA ChainPara;
    PCCERT_CHAIN_CONTEXT pChainContext = NULL;

    LPSTR rgszUsages[] = {  (CHAR*)szOID_PKIX_KP_SERVER_AUTH,
                            (CHAR*)szOID_SERVER_GATED_CRYPTO,
                            (CHAR*)szOID_SGC_NETSCAPE };
    DWORD cUsages = sizeof(rgszUsages) / sizeof(LPSTR);

    PWSTR pwszServerName = NULL;
    DWORD cchServerName;
    LONG Status;

    if ( Cert == NULL )
    {
        Status = SEC_E_WRONG_PRINCIPAL;
        goto cleanup;
    }


    //
    // Convert server name to unicode.
    //

    if ( ServerIp == NULL || strlen(ServerIp) == 0 )
    {
        Status = SEC_E_WRONG_PRINCIPAL;
        goto cleanup;
    }

    cchServerName = MultiByteToWideChar(CP_ACP, 0, ServerIp, -1, NULL, 0);
    pwszServerName = (PWSTR) LocalAlloc(LMEM_FIXED, cchServerName * sizeof(WCHAR));
    if ( pwszServerName == NULL )
    {
        Status = SEC_E_INSUFFICIENT_MEMORY;
        goto cleanup;
    }
    cchServerName = MultiByteToWideChar(CP_ACP, 0, ServerIp, -1, pwszServerName, cchServerName);
    if ( cchServerName == 0 )
    {
        Status = SEC_E_WRONG_PRINCIPAL;
        goto cleanup;
    }


    //
    // Build certificate chain.
    //

    ZeroMemory(&ChainPara, sizeof(ChainPara));
    ChainPara.cbSize = sizeof(ChainPara);
    ChainPara.RequestedUsage.dwType = USAGE_MATCH_TYPE_OR;
    ChainPara.RequestedUsage.Usage.cUsageIdentifier = cUsages;
    ChainPara.RequestedUsage.Usage.rgpszUsageIdentifier = rgszUsages;

    if ( !CertGetCertificateChain(
                            NULL,
                            Cert,
                            NULL,
                            Cert->hCertStore,
                            &ChainPara,
                            0,
                            NULL,
                            &pChainContext) )
    {
        Status = GetLastError();
        fprintf(out, "ERROR (0x%x) CertGetCertificateChain!\n", Status);
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

    memset(&PolicyPara, 0, sizeof(PolicyPara));
    PolicyPara.cbSize            = sizeof(PolicyPara);
    PolicyPara.pvExtraPolicyPara = &polHttps;

    memset(&PolicyStatus, 0, sizeof(PolicyStatus));
    PolicyStatus.cbSize = sizeof(PolicyStatus);

    if ( !CertVerifyCertificateChainPolicy(
                            CERT_CHAIN_POLICY_SSL,
                            pChainContext,
                            &PolicyPara,
                            &PolicyStatus) )
    {
        Status = GetLastError();
        fprintf(out, "ERROR (0x%x): CertVerifyCertificateChainPolicy!\n", Status);
        goto cleanup;
    }

    if ( PolicyStatus.dwError )
    {
        Status = PolicyStatus.dwError;
        DisplayWinVerifyTrustError(Status, out); 
        if ( PolicyStatus.dwError == CERT_E_UNTRUSTEDROOT )
            fprintf(out, "skipping\n");
        else
            goto cleanup;
    }


    Status = SEC_E_OK;

cleanup:

    if(pChainContext)
    {
        CertFreeCertificateChain(pChainContext);
    }

    if(pwszServerName)
    {
        LocalFree(pwszServerName);
    }

    return Status;
}

BOOL
SSPINegotiateLoop(
    _In_ SOCKET Socket,
    _Out_ PCtxtHandle phContext,
    _In_ PCredHandle phCred,
    _In_ BOOL fDoInitialRead,
    _In_ BOOL NewContext,
    _In_ PBYTE pbIoBuffer,
    _In_ ULONG cbIoBuffer
)
{
    TimeStamp tsExpiry;
    SECURITY_STATUS scRet;
    SecBufferDesc InBuffer;
    SecBufferDesc OutBuffer;
    SecBuffer InBuffers[2];
    SecBuffer OutBuffers[1];
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
    //  set OutBuffer for InitializeSecurityContext call
    //

    OutBuffer.cBuffers = 1;
    OutBuffer.pBuffers = OutBuffers;
    OutBuffer.ulVersion = SECBUFFER_VERSION;


    scRet = SEC_I_CONTINUE_NEEDED;
    cbIoBuffer = 0;

    while( scRet == SEC_I_CONTINUE_NEEDED ||
           scRet == SEC_E_INCOMPLETE_MESSAGE ||
           scRet == SEC_I_INCOMPLETE_CREDENTIALS) 
    {
        if ( 0 == cbIoBuffer || scRet == SEC_E_INCOMPLETE_MESSAGE )
        {
            if ( fDoRead )
            {
                cbData = recv(Socket, (PCHAR)(pbIoBuffer+cbIoBuffer), cbIoBufferLength, 0);

                if ( cbData == SOCKET_ERROR || cbData == 0 )
                {
                    fprintf(out, "ERROR (0x%x): recv failed\n", GetLastError());
                    return FALSE;
                }

                fprintf(out, "\nReceived 0x%x (handshake) bytes from client\n", cbData);

#ifdef DEBUG_PRINT_HEX_DUMP
                PrintHexDump(cbData, pbIoBuffer+cbIoBuffer, out);
#endif
                cbIoBuffer += cbData;
            }
            else
            {
                fDoRead = TRUE;
            }
        }


        //
        // InBuffers[1] is for getting extra data that
        //  SSPI/SCHANNEL doesn't proccess on this
        //  run around the loop.
        //

        InBuffers[0].pvBuffer = pbIoBuffer;
        InBuffers[0].cbBuffer = cbIoBuffer;
        InBuffers[0].BufferType = SECBUFFER_TOKEN;

        InBuffers[1].pvBuffer = NULL;
        InBuffers[1].cbBuffer = 0;
        InBuffers[1].BufferType = SECBUFFER_EMPTY;

        InBuffer.cBuffers = 2;
        InBuffer.pBuffers = InBuffers;
        InBuffer.ulVersion = SECBUFFER_VERSION;


        //
        // Initialize these so if we fail, pvBuffer contains NULL,
        // so we don't try to free random garbage at the quit
        //

        OutBuffers[0].pvBuffer = NULL;
        OutBuffers[0].BufferType = SECBUFFER_TOKEN;
        OutBuffers[0].cbBuffer = 0;


        scRet = g_pSSPI->AcceptSecurityContext(
                        phCred,
                        (fInitContext?NULL:phContext),
                        &InBuffer,
                        dwSSPIFlags,
                        0,
                        (fInitContext?phContext:NULL),
                        &OutBuffer,
                        &dwSSPIOutFlags,
                        &tsExpiry);

        fInitContext = FALSE;

        if ( scRet == SEC_E_OK ||
             scRet == SEC_I_CONTINUE_NEEDED ||
             (FAILED(scRet) && (0 != (dwSSPIOutFlags & ISC_RET_EXTENDED_ERROR))))
        {
            if  (OutBuffers[0].cbBuffer != 0    &&
                 OutBuffers[0].pvBuffer != NULL )
            {
                // Send response to server if there is one
                cbData = send(Socket,
                              (PCHAR)OutBuffers[0].pvBuffer,
                              OutBuffers[0].cbBuffer,
                              0);

                fprintf(out, "\nSend 0x%x handshake bytes to client\n", OutBuffers[0].cbBuffer);

#ifdef DEBUG_PRINT_HEX_DUMP
                PrintHexDump(OutBuffers[0].cbBuffer, OutBuffers[0].pvBuffer, out);
#endif

                g_pSSPI->FreeContextBuffer(OutBuffers[0].pvBuffer);
                OutBuffers[0].pvBuffer = NULL;
            }
        }


        if ( scRet == SEC_E_OK )
        {
            if ( InBuffers[1].BufferType == SECBUFFER_EXTRA )
            {
                memcpy(pbIoBuffer,
                       (LPBYTE) (pbIoBuffer + (cbIoBuffer - InBuffers[1].cbBuffer)),
                       InBuffers[1].cbBuffer);
                cbIoBuffer = InBuffers[1].cbBuffer;
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
            fprintf(out, "ERROR (0x%x): Accept Security Context Failed : %s\n", scRet, getSecErrorString(scRet));
            return FALSE;
        }

        if ( scRet != SEC_E_INCOMPLETE_MESSAGE &&
             scRet != SEC_I_INCOMPLETE_CREDENTIALS)
        {
            if ( InBuffers[1].BufferType == SECBUFFER_EXTRA )
            {
                memcpy(pbIoBuffer,
                       (LPBYTE) (pbIoBuffer + (cbIoBuffer - InBuffers[1].cbBuffer)),
                        InBuffers[1].cbBuffer);
                cbIoBuffer = InBuffers[1].cbBuffer;
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
    _In_ CtxtHandle *phContext,
    _In_ PSecurityFunctionTable SSPI
)
{
    SECURITY_STATUS Status;
    SecPkgContext_ConnectionInfo ConnectionInfo;

    Status = SSPI->QueryContextAttributes(
        phContext,
        SECPKG_ATTR_CONNECTION_INFO,
        (PVOID)&ConnectionInfo
    );
    if ( Status != SEC_E_OK )
    {
        fprintf(out, "ERROR (0x%x): querying connection info\n", Status);
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
    _Out_ SecPkgContext_StreamSizes* pSizes,
    _In_ CtxtHandle *phContext
)
{
    int scRet = g_pSSPI->QueryContextAttributes(phContext,
                                   SECPKG_ATTR_STREAM_SIZES,
                                   pSizes);
    if ( scRet != SEC_E_OK )
    {
        fprintf(out, "ERROR (0x%x): reading SECPKG_ATTR_STREAM_SIZES\n", scRet);
        return scRet;
    }
#ifdef DEBUG_PRINT
    fprintf(out, "Sizes:\n - Header: 0x%x\n - Trailer: 0x%x\n - MaxMessage: 0x%x\n - Buffers: 0x%x\n - BlockSize: 0x%x\n",
        pSizes->cbHeader,
        pSizes->cbTrailer,
        pSizes->cbMaximumMessage,
        pSizes->cBuffers,
        pSizes->cbBlockSize
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
        fprintf(out, "ERROR: Out of memory (2)\n");
        *cbBuffer = 0;
        return SEC_E_INTERNAL_ERROR;
    }

    return 0;
}

SECURITY_STATUS sendSChannelData(
    _In_ PUCHAR pbMessage,
    _In_ ULONG cbMessage, 
    _In_ SOCKET Socket,
    _In_ CtxtHandle *phContext,
    _In_ SecPkgContext_StreamSizes* pSizes,
    _In_ PBYTE pbIoBuffer,
    _In_ ULONG cbIoBuffer
)
{
    SECURITY_STATUS scRet;
    SecBufferDesc Message;
    SecBuffer Buffers[4];

    DWORD cbData;

    UNREFERENCED_PARAMETER(cbIoBuffer);

    // Build the message offset into the data buffer by "header size" bytes. 
    // This enables Schannel to perform the encryption in place, which is a significant performance win.

      
#if defined(DEBUG_PRINT_HEX_DUMP) && defined(DEBUG_PRINT_MESSAGE)
    fprintf(out, "pbMessage (0x%x):\n", cbMessage);
    PrintHexDump(cbMessage, pbMessage, out);
    fprintf(out, "\n");
#endif

    //
    // Encrypt the HTTP request.
    //

    Buffers[0].pvBuffer = pbIoBuffer;
    Buffers[0].cbBuffer = pSizes->cbHeader;
    Buffers[0].BufferType = SECBUFFER_STREAM_HEADER;

    Buffers[1].pvBuffer = pbMessage;
    Buffers[1].cbBuffer = cbMessage;
    Buffers[1].BufferType = SECBUFFER_DATA;

    Buffers[2].pvBuffer = pbMessage + cbMessage;
    Buffers[2].cbBuffer = pSizes->cbTrailer;
    Buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;

    Buffers[3].BufferType = SECBUFFER_EMPTY;

    Message.ulVersion = SECBUFFER_VERSION;
    Message.cBuffers = 4;
    Message.pBuffers = Buffers;
     
    scRet = g_pSSPI->EncryptMessage(
                        phContext, 
                        0, 
                        &Message, 
                        0
                    );

    if ( FAILED(scRet) )
    {
        fprintf(out, "ERROR (0x%x): %s returned by EncryptMessage\n", scRet, getSecErrorString(scRet));
        return scRet;
    }


    // 
    // Send the encrypted data to the server.
    //

    cbData = send(Socket,
                  (PCHAR)pbIoBuffer,
                  Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer,
                  0);
    if ( cbData == SOCKET_ERROR || cbData == 0 )
    {
        //deleteSecurityContext(phContext);

        scRet = WSAGetLastError();
        fprintf(out, "ERROR (0x%x): sending data to server (3)\n", scRet);
        if ( scRet == WSAEWOULDBLOCK || scRet == 0 )
        {
            fprintf(out, " retry\n");
            Sleep(SEND_LOOP_SLEEP);
            return sendSChannelData(
                        pbMessage,
                        cbMessage, 
                        Socket,
                        phContext,
                        pSizes,
                        pbIoBuffer,
                        cbIoBuffer
                    );
        }
        else
        {
            fprintf(out, " break\n");
            return scRet;
        }
    }

#ifdef DEBUG_PRINT
    fprintf(out, "0x%x bytes of application data sent\n", cbData);
#endif
#ifdef DEBUG_PRINT_HEX_DUMP
    PrintHexDump(cbData, pbIoBuffer, out);
    fprintf(out, "\n");
#endif
    
    return SEC_E_OK;
}

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
)
{
    SECURITY_STATUS scRet = SEC_E_OK;
    int msgRet = 0;
    SecBufferDesc Message;
    SecBuffer Buffers[4];
    SecBuffer *pDataBuffer;
    SecBuffer *pExtraBuffer;
    SecBuffer ExtraBuffer;

    DWORD cbIoBufferLength = cbIoBuffer;

    DWORD cbData;
    INT i;

    UNREFERENCED_PARAMETER(pSizes);
    
#ifdef DEBUG_PRINT
    fprintf(out, "receiveSChannelData\n");
#endif

    cbIoBuffer = 0;

    Message.ulVersion = SECBUFFER_VERSION;
    Message.cBuffers = 4;
    Message.pBuffers = Buffers;

    while ( *running )
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
                if ( cbData == WSAEWOULDBLOCK )
                {
                    Sleep(RECEIVE_LOOP_SLEEP);
                    continue;
                }
                else
                {
                    fprintf(out, "ERROR (0x%x): recv data error\n", cbData);
                    scRet = SEC_E_INTERNAL_ERROR;
                    break;
                }
            }
            else if ( cbData == 0 )
            {
                // Server disconnected.
                if ( cbIoBuffer )
                {
                    fprintf(out, "Unexpected Disconnection while receiving\n");
                    scRet = SEC_E_INTERNAL_ERROR;
                    break;
                }
                else
                {
                    fprintf(out, "Received 0 bytes\n");
                    break;
                }
            }
            else
            {
#ifdef DEBUG_PRINT
                fprintf(out, "0x%x bytes of (encrypted) application data received\n", cbData);
#endif
#ifdef DEBUG_PRINT_HEX_DUMP
                PrintHexDump(cbData, pbIoBuffer + cbIoBuffer, out);
                fprintf(out, "\n");
#endif

                cbIoBuffer += cbData;
            }
        }

        // 
        // Attempt to decrypt the received data.
        //

        Buffers[0].pvBuffer = pbIoBuffer;
        Buffers[0].cbBuffer = cbIoBuffer;
        Buffers[0].BufferType = SECBUFFER_DATA;

        Buffers[1].BufferType = SECBUFFER_EMPTY;
        Buffers[2].BufferType = SECBUFFER_EMPTY;
        Buffers[3].BufferType = SECBUFFER_EMPTY;

        scRet = g_pSSPI->DecryptMessage(phContext, &Message, 0, NULL);

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
            fprintf(out, "SEC_I_CONTEXT_EXPIRED\n");
            break;
        }
        if ( scRet != SEC_E_OK && 
             scRet != SEC_I_RENEGOTIATE )
        {
            fprintf(out, "ERROR (0x%x): DecryptMessage %s\n", scRet, getSecErrorString(scRet));
            break;
        }

        // Locate data and (optional) extra buffers.
        pDataBuffer  = NULL;
        pExtraBuffer = NULL;
        for ( i = 1; i < 4; i++ )
        {

            if ( pDataBuffer == NULL && Buffers[i].BufferType == SECBUFFER_DATA )
            {
                pDataBuffer = &Buffers[i];
            }
            if ( pExtraBuffer == NULL && Buffers[i].BufferType == SECBUFFER_EXTRA )
            {
                pExtraBuffer = &Buffers[i];
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

        // Process the decrypted data.
        if ( pDataBuffer )
        {
#ifdef DEBUG_PRINT_MESSAGE
            fprintf(out, "Decrypted data: 0x%x bytes\n", pDataBuffer->cbBuffer);
#endif
#if defined(DEBUG_PRINT_MESSAGE) && defined(DEBUG_PRINT_HEX_DUMP)
            PrintHexDump(pDataBuffer->cbBuffer, pDataBuffer->pvBuffer, out);
            fprintf(out, "\n");
#endif
            
            msgRet = handleMessage(
                        pDataBuffer->pvBuffer, 
                        pDataBuffer->cbBuffer,
                        pSizes,
                        type,
                        running
                    );
            if ( msgRet != 0 || !(*running) )
            {
                // pbIoBuffer may be invalid now
                *running = false;
                break;
            }
        }

        if ( scRet == SEC_I_RENEGOTIATE )
        {
            if ( type == ENGINE_TYPE_CLIENT )
            {
                // The server wants to perform another handshake
                // sequence.

                fprintf(out, "Server requested renegotiate!\n");

                scRet = ClientHandshakeLoop(Socket, 
                                            phClientCreds, 
                                            phContext, 
                                            FALSE, 
                                            &ExtraBuffer);
                if ( scRet != SEC_E_OK )
                {
                    break;
                }

                // Move any "extra" data to the input buffer.
                if ( ExtraBuffer.pvBuffer )
                {
                    MoveMemory(pbIoBuffer, ExtraBuffer.pvBuffer, ExtraBuffer.cbBuffer);
                    cbIoBuffer = ExtraBuffer.cbBuffer;
                }
            }
            else
            {
                fprintf(out, "Client requested renegotiate : unhandled!\n");
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
    _In_ PCredHandle phCreds,
    _Inout_ CtxtHandle *phContext,
    _In_ ULONG type
)
{
    DWORD dwType;
    PBYTE pbMessage;
    DWORD cbMessage;
    DWORD cbData;

    SecBufferDesc OutBuffer;
    SecBuffer OutBuffers[1];
    DWORD dwSSPIFlags;
    DWORD dwSSPIOutFlags;
    TimeStamp tsExpiry;
    DWORD Status = 0;
    
    fprintf(out, "Disconnect()\n");

    //
    // Notify schannel that we are about to close the connection.
    //

    dwType = SCHANNEL_SHUTDOWN;

    if ( *Socket == INVALID_SOCKET )
        goto cleanup;
    if ( phCreds == NULL || (phCreds->dwLower == 0 && phCreds->dwUpper == 0) )
        goto cleanup;
    if ( phContext == NULL || (phContext->dwLower == 0 && phContext->dwUpper == 0) )
        goto cleanup;

    OutBuffers[0].pvBuffer = &dwType;
    OutBuffers[0].BufferType = SECBUFFER_TOKEN;
    OutBuffers[0].cbBuffer = sizeof(dwType);

    OutBuffer.cBuffers = 1;
    OutBuffer.pBuffers = OutBuffers;
    OutBuffer.ulVersion = SECBUFFER_VERSION;

    Status = g_pSSPI->ApplyControlToken(phContext, &OutBuffer);

    if ( FAILED(Status) ) 
    {
        fprintf(out, "ERROR (0x%x): ApplyControlToken\n", Status);
        goto cleanup;
    }

    //
    // Build an SSL close notify message.
    //

    dwSSPIFlags =   ASC_REQ_SEQUENCE_DETECT     |
                    ASC_REQ_REPLAY_DETECT       |
                    ASC_REQ_CONFIDENTIALITY     |
                    ASC_REQ_EXTENDED_ERROR      |
                    ASC_REQ_ALLOCATE_MEMORY     |
                    ASC_REQ_STREAM;

    OutBuffers[0].pvBuffer   = NULL;
    OutBuffers[0].BufferType = SECBUFFER_TOKEN;
    OutBuffers[0].cbBuffer   = 0;

    OutBuffer.cBuffers  = 1;
    OutBuffer.pBuffers  = OutBuffers;
    OutBuffer.ulVersion = SECBUFFER_VERSION;
    
    if ( type == ENGINE_TYPE_SERVER )
    {
        Status = g_pSSPI->AcceptSecurityContext(
                        phCreds,
                        phContext,
                        NULL,
                        dwSSPIFlags,
                        0,
                        NULL,
                        &OutBuffer,
                        &dwSSPIOutFlags,
                        &tsExpiry);

        if ( FAILED(Status) ) 
        {
            fprintf(out, "ERROR (0x%x): AcceptSecurityContext\n", Status);
            goto cleanup;
        }
    }
    else if ( type == ENGINE_TYPE_CLIENT )
    {
        Status = g_pSSPI->InitializeSecurityContextA(
                        phCreds,
                        phContext,
                        NULL,
                        dwSSPIFlags,
                        0,
                        0,
                        NULL,
                        0,
                        phContext,
                        &OutBuffer,
                        &dwSSPIOutFlags,
                        &tsExpiry);
    
        if ( FAILED(Status) ) 
        {
            fprintf(out, "ERROR (0x%x): InitializeSecurityContext\n", Status);
            goto cleanup;
        }
    }

    pbMessage = (PBYTE)OutBuffers[0].pvBuffer;
    cbMessage = OutBuffers[0].cbBuffer;


    //
    // Send the close notify message to the client.
    //

    if ( pbMessage != NULL && cbMessage != 0 )
    {
        cbData = send(*Socket, (PCHAR)pbMessage, cbMessage, 0);
        if ( cbData == SOCKET_ERROR || cbData == 0 )
        {
            Status = WSAGetLastError();
            fprintf(out, "ERROR (0x%x): Sending close notify : %s\n", Status, getWSAErrorString(Status));
            goto cleanup;
        }
        
        fprintf(out, "Sending Close Notify\n");
#ifdef DEBUG_PRINT
        fprintf(out, "\n0x%x bytes of handshake data sent\n", cbData);
#endif
#ifdef DEBUG_PRINT_HEX_DUMP
        PrintHexDump(cbData, pbMessage, out);
        fprintf(out, "\n");
#endif

        // Free output buffer.
        g_pSSPI->FreeContextBuffer(pbMessage);
    }
    

cleanup:
    deleteSecurityContext(phContext);
    if ( *Socket != INVALID_SOCKET )
        closesocket(*Socket);
    *Socket = INVALID_SOCKET;

    return Status;
}

LONG
VerifyClientCertificate(
    _In_ PCCERT_CONTEXT Cert,
    _In_ DWORD CertFlags
)
{
    HTTPSPolicyCallbackData polHttps;
    CERT_CHAIN_POLICY_PARA PolicyPara;
    CERT_CHAIN_POLICY_STATUS PolicyStatus;
    CERT_CHAIN_PARA ChainPara;
    PCCERT_CHAIN_CONTEXT pChainContext = NULL;
    LPSTR pszUsage;

    DWORD Status;

    if ( Cert == NULL )
    {
        return SEC_E_WRONG_PRINCIPAL;
    }


    //
    // Build certificate chain.
    //

    pszUsage = (CHAR*)szOID_PKIX_KP_CLIENT_AUTH;

    ZeroMemory(&ChainPara, sizeof(ChainPara));
    ChainPara.cbSize = sizeof(ChainPara);
    ChainPara.RequestedUsage.dwType = USAGE_MATCH_TYPE_OR;
    ChainPara.RequestedUsage.Usage.cUsageIdentifier = 1;
    ChainPara.RequestedUsage.Usage.rgpszUsageIdentifier = &pszUsage;

    if ( !CertGetCertificateChain(
                            NULL,
                            Cert,
                            NULL,
                            Cert->hCertStore,
                            &ChainPara,
                            0,
                            NULL,
                            &pChainContext) )
    {
        Status = GetLastError();
        fprintf(out, "ERROR (0x%x): returned by CertGetCertificateChain!\n", Status);
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

    memset(&PolicyPara, 0, sizeof(PolicyPara));
    PolicyPara.cbSize = sizeof(PolicyPara);
    PolicyPara.pvExtraPolicyPara = &polHttps;

    memset(&PolicyStatus, 0, sizeof(PolicyStatus));
    PolicyStatus.cbSize = sizeof(PolicyStatus);

    if ( !CertVerifyCertificateChainPolicy(
                            CERT_CHAIN_POLICY_SSL,
                            pChainContext,
                            &PolicyPara,
                            &PolicyStatus) )
    {
        Status = GetLastError();
        fprintf(out, "ERROR (0x%x): returned by CertVerifyCertificateChainPolicy!\n", Status);
        goto cleanup;
    }

    if ( PolicyStatus.dwError )
    {
        Status = PolicyStatus.dwError;
        DisplayWinVerifyTrustError(Status, out); 
        if ( PolicyStatus.dwError == CERT_E_UNTRUSTEDROOT )
            fprintf(out, "skipping\n");
        else
            goto cleanup;
    }

    Status = SEC_E_OK;

cleanup:

    if ( pChainContext )
    {
        CertFreeCertificateChain(pChainContext);
    }

    return Status;
}

void SChannel_clean(
    _Out_ PCtxtHandle Context,
    _Out_ PCredHandle ClientCreds,
    _Out_ PCredHandle ServerCreds,
    _Out_ HCERTSTORE* CertStore
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
    _Out_ PCredHandle Creds
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
    _Out_ CtxtHandle *phContext
)
{
    if ( phContext != NULL && phContext->dwLower != 0 && phContext->dwUpper != 0 )
    {
        g_pSSPI->DeleteSecurityContext(phContext);
        phContext->dwLower = 0;
        phContext->dwUpper = 0;
    }
}

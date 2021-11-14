#define _CRT_SECURE_NO_WARNINGS


#include <stdio.h>

#include "../dbg.h"
#include "common.h"
#include "../files/Files.h"

//#pragma warning( disable : 4057 4245 4477 4459)



void printBytes(
    PVOID buffer, 
    ULONG n, 
    INT bs,
    const char* prefix,
    FILE* out
)
{
    PBYTE b = (PBYTE)buffer;
    for ( ULONG i = 0; i < n; i++ )
    {
        if ( ( bs > 0 ) && (i % bs == 0 ) )
            fprintf(out, "\n%s", prefix);
        fprintf(out, "%02x ", b[i]);
    }
    fprintf(out, "\n");
}

void printReverseBytes(
    PVOID buffer, 
    ULONG n, 
    INT bs,
    const char* prefix,
    FILE* out
)
{
    PBYTE b = (PBYTE)buffer;
    ULONG j = n;
    for ( ULONG i = 0; i < n; i++ )
    {
        j--;
        if ( ( bs > 0 ) && (i % bs == 0 ) )
            fprintf(out, "\n%s", prefix);
        fprintf(out, "%02x ", b[j]);
    }
    fprintf(out, "\n");
}

void 
PrintHexDump(
    DWORD length, 
    PVOID buf,
    FILE* out
)
{
    DWORD i,count,index;
    CHAR rgbDigits[]="0123456789abcdef";
    CHAR rgbLine[100];
    char cbLine;
    PBYTE buffer = (PBYTE)buf;

    for ( index = 0; length; length -= count, buffer += count, index += count) 
    {
        count = (length > 16) ? 16:length;

        sprintf(rgbLine, "%4.4x  ",index);
        cbLine = 6;

        for ( i = 0; i < count; i++ )  
        {
            rgbLine[cbLine++] = rgbDigits[buffer[i] >> 4];
            rgbLine[cbLine++] = rgbDigits[buffer[i] & 0x0f];
            if(i == 7) 
            {
                rgbLine[cbLine++] = ' ';
                rgbLine[cbLine++] = ' ';
            } 
            else 
            {
                rgbLine[cbLine++] = ' ';
            }
        }
        for(; i < 16; i++) 
        {
            rgbLine[cbLine++] = ' ';
            rgbLine[cbLine++] = ' ';
            rgbLine[cbLine++] = ' ';
        }

        rgbLine[cbLine++] = ' ';

        for(i = 0; i < count; i++) 
        {
            if(buffer[i] < 32 || buffer[i] > 126 || buffer[i] == '%') 
            {
                rgbLine[cbLine++] = '.';
            } 
            else 
            {
                rgbLine[cbLine++] = buffer[i];
            }
        }

        rgbLine[cbLine++] = 0;
        fprintf(out, "%s\n", rgbLine);
    }
}

void printSecPackages(FILE* out)
{
    ULONG cPackages = 0;
    PSecPkgInfo pPackageInfo = NULL;
    int s = EnumerateSecurityPackages(
        &cPackages, 
        &pPackageInfo
    );
    if ( s != 0 )
    {
        fprintf(out, "ERROR (0x%x): EnumerateSecurityPackages\n", s);
        return;
    }

    for ( ULONG i = 0; i < cPackages; i++ )
    {
        fprintf(out, "%u / %u\n", i+1, cPackages);
        printSecPkgInfo(&pPackageInfo[i], out);
        fprintf(out, "\n");
    }

    FreeContextBuffer(pPackageInfo);
}

void printSecPkgInfo(PSecPkgInfo info, FILE* out)
{
    fprintf(out, "fCapabilities: 0x%x\n", info->fCapabilities);
    fprintf(out, "wVersion: 0x%x\n", info->wVersion);
    fprintf(out, "wRPCID: 0x%x\n", info->wRPCID);
    fprintf(out, "cbMaxToken: 0x%x\n", info->cbMaxToken);
    fprintf(out, "Name: %s\n", info->Name);
    fprintf(out, "Comment: %s\n", info->Comment);
}

void printCert(
    PCCERT_CONTEXT cert,
    FILE* out
)
{
    fprintf(out, "CertEncodingType: 0x%x\n", cert->dwCertEncodingType);
    fprintf(out, "CertEncoded (%p):", cert->pbCertEncoded);
    printBytes(cert->pbCertEncoded, cert->cbCertEncoded, 0x10, "", out);
    fprintf(out, "CertInfo: %p\n", cert->pCertInfo);
    fprintf(out, "  Version: 0x%x\n", cert->pCertInfo->dwVersion);
    fprintf(out, "  SerialNumber (%p):", &cert->pCertInfo->SerialNumber);
    printReverseBytes(cert->pCertInfo->SerialNumber.pbData, cert->pCertInfo->SerialNumber.cbData, 0x10, "  ", out);
    fprintf(out, "  SignatureAlgorithm (%p):\n", &cert->pCertInfo->SignatureAlgorithm);
    fprintf(out, "    ObjId %s:\n", cert->pCertInfo->SignatureAlgorithm.pszObjId);
    fprintf(out, "    Parameters (%p):", &cert->pCertInfo->SignatureAlgorithm.Parameters);
    printBytes(cert->pCertInfo->SignatureAlgorithm.Parameters.pbData, cert->pCertInfo->SignatureAlgorithm.Parameters.cbData, 0x10, "    ", out);
    fprintf(out, "  Issuer (%p):", &cert->pCertInfo->Issuer);
    printBytes(cert->pCertInfo->Issuer.pbData, cert->pCertInfo->Issuer.cbData, 0x10, "  ", out);
    fprintf(out, "  NotBefore 0x%llx\n", (ULONGLONG)*(ULONGLONG*)&cert->pCertInfo->NotBefore);
    fprintf(out, "  NotAfter 0x%llx\n", (ULONGLONG)*(ULONGLONG*)&cert->pCertInfo->NotAfter);
    fprintf(out, "  NotAfter 0x%llx\n", (ULONGLONG)*(ULONGLONG*)&cert->pCertInfo->NotAfter);
    fprintf(out, "  Subject (%p):", &cert->pCertInfo->Subject);
    printBytes(cert->pCertInfo->Subject.pbData, cert->pCertInfo->Subject.cbData, 0x10, "  ", out);
    fprintf(out, "  SubjectPublicKeyInfo (%p):\n", &cert->pCertInfo->SubjectPublicKeyInfo);
    fprintf(out, "    Algorithm (%p):\n", &cert->pCertInfo->SubjectPublicKeyInfo.Algorithm);
    fprintf(out, "      ObjId: %s\n", cert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId);
    fprintf(out, "      Parameters (%p):", &cert->pCertInfo->SubjectPublicKeyInfo.Algorithm.Parameters);
    printBytes(cert->pCertInfo->SubjectPublicKeyInfo.Algorithm.Parameters.pbData, cert->pCertInfo->SubjectPublicKeyInfo.Algorithm.Parameters.cbData, 0x10, "      ", out);
    fprintf(out, "    PublicKey (%p):", &cert->pCertInfo->SubjectPublicKeyInfo.PublicKey);
    printBytes(cert->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData, cert->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData, 0x10, "    ", out);
    fprintf(out, "    UnusedBits: 0x%x\n", cert->pCertInfo->SubjectPublicKeyInfo.PublicKey.cUnusedBits);
    fprintf(out, "  IssuerUniqueId (%p):", &cert->pCertInfo->IssuerUniqueId);
    printBytes(cert->pCertInfo->IssuerUniqueId.pbData, cert->pCertInfo->IssuerUniqueId.cbData, 0x10, "    ", out);
    fprintf(out, "    UnusedBits: 0x%x\n", cert->pCertInfo->IssuerUniqueId.cUnusedBits);
    fprintf(out, "  SubjectUniqueId (%p):", &cert->pCertInfo->SubjectUniqueId);
    printBytes(cert->pCertInfo->SubjectUniqueId.pbData, cert->pCertInfo->SubjectUniqueId.cbData, 0x10, "    ", out);
    fprintf(out, "    UnusedBits: 0x%x\n", cert->pCertInfo->SubjectUniqueId.cUnusedBits);
    //fprintf(out, " cExtensions: 0x%x\n", cert->pCertInfo->cExtension);
    for ( ULONG i = 0; i < cert->pCertInfo->cExtension; i++ )
    {
        PCERT_EXTENSION ext = &cert->pCertInfo->rgExtension[i];
        fprintf(out, "  %u/%u Extension (%p):\n", (i+1), cert->pCertInfo->cExtension, ext);
        fprintf(out, "    ObjId: %s\n", ext->pszObjId);
        fprintf(out, "    Critical: %u\n", ext->fCritical);
        fprintf(out, "    Value (%p):", &ext->Value);
        printBytes(ext->Value.pbData, ext->Value.cbData, 0x10, "    ", out);
    }
    fprintf(out, "CertStore: %p\n", cert->hCertStore);
    fprintf(out, "\n");
}

int saveCert(
    PCCERT_CONTEXT cert,
    const char* label,
    const char* dir,
    FILE* out
)
{
    const char* d = (dir==NULL) ? "." : dir;
    char path[MAX_PATH];
    ZeroMemory(path, MAX_PATH);
    sprintf_s(path, MAX_PATH, 
        "%s\\%s.der",
        d,
        label
    );

    if ( fileExists(path) )
        return 0;

    FILE* file = NULL;
    int err = fopen_s(&file, path, "wb");
    if ( err != 0 )
    {
        fprintf(out, "ERROR (0x%x): Open file failed\n", err);
        return -1;
    }
    errno = 0;
    size_t w = fwrite(cert->pbCertEncoded, 1, cert->cbCertEncoded, file);
    err = errno;
    if ( w != cert->cbCertEncoded )
    {
        fprintf(out, "ERROR (0x%x): Writing file failed.", err);
        goto clean;
    }
clean:
    fclose(file);
    return err;
}

void
DisplayWinVerifyTrustError(
    DWORD Status,
    FILE* out
)
{
    const char* pszName = NULL;

    switch(Status)
    {
    case CERT_E_EXPIRED:                pszName = "CERT_E_EXPIRED";                 break;
    case CERT_E_VALIDITYPERIODNESTING:  pszName = "CERT_E_VALIDITYPERIODNESTING";   break;
    case CERT_E_ROLE:                   pszName = "CERT_E_ROLE";                    break;
    case CERT_E_PATHLENCONST:           pszName = "CERT_E_PATHLENCONST";            break;
    case CERT_E_CRITICAL:               pszName = "CERT_E_CRITICAL";                break;
    case CERT_E_PURPOSE:                pszName = "CERT_E_PURPOSE";                 break;
    case CERT_E_ISSUERCHAINING:         pszName = "CERT_E_ISSUERCHAINING";          break;
    case CERT_E_MALFORMED:              pszName = "CERT_E_MALFORMED";               break;
    case CERT_E_UNTRUSTEDROOT:          pszName = "CERT_E_UNTRUSTEDROOT";           break;
    case CERT_E_CHAINING:               pszName = "CERT_E_CHAINING";                break;
    case TRUST_E_FAIL:                  pszName = "TRUST_E_FAIL";                   break;
    case CERT_E_REVOKED:                pszName = "CERT_E_REVOKED";                 break;
    case CERT_E_UNTRUSTEDTESTROOT:      pszName = "CERT_E_UNTRUSTEDTESTROOT";       break;
    case CERT_E_REVOCATION_FAILURE:     pszName = "CERT_E_REVOCATION_FAILURE";      break;
    case CERT_E_CN_NO_MATCH:            pszName = "CERT_E_CN_NO_MATCH";             break;
    case CERT_E_WRONG_USAGE:            pszName = "CERT_E_WRONG_USAGE";             break;
    default:                            pszName = "(unknown)";                      break;
    }

    fprintf(out, "ERROR (0x%x): (%s) returned by CertVerifyCertificateChainPolicy!\n", 
        Status, pszName);
}

const char*
getSecErrorString(
    DWORD Status
)
{
    switch(Status)
    {
    case SEC_E_ALGORITHM_MISMATCH: return "The client and server cannot communicate, because they do not possess a common algorithm"; break;
    case SEC_E_BUFFER_TOO_SMALL: return "SEC_E_BUFFER_TOO_SMALL"; break;
    case SEC_E_CERT_EXPIRED: return "SEC_E_CERT_EXPIRED"; break;
    case SEC_E_CERT_UNKNOWN: return "SEC_E_CERT_UNKNOWN"; break;
    case SEC_E_CONTEXT_EXPIRED: return "SEC_E_CONTEXT_EXPIRED"; break;
    case SEC_E_CRYPTO_SYSTEM_INVALID: return "SEC_E_CRYPTO_SYSTEM_INVALID"; break;
    case SEC_E_DECRYPT_FAILURE: return "The specified data could not be decrypted"; break;
    case SEC_E_ENCRYPT_FAILURE: return "The specified data could not be encrypted"; break;
    case SEC_E_INSUFFICIENT_MEMORY: return "SEC_E_INSUFFICIENT_MEMORY"; break;
    case SEC_E_INTERNAL_ERROR: return "The Local Security Authority cannot be contacted"; break;
    case SEC_E_INVALID_HANDLE: return "SEC_E_INVALID_HANDLE"; break;
    case SEC_E_INVALID_TOKEN: return "SEC_E_INVALID_TOKEN"; break;
    case SEC_E_NO_CREDENTIALS: return "SEC_E_NO_CREDENTIALS"; break;
    case SEC_E_QOP_NOT_SUPPORTED: return "SEC_E_QOP_NOT_SUPPORTED"; break;
    case SEC_E_UNKNOWN_CREDENTIALS: return "SEC_E_UNKNOWN_CREDENTIALS"; break;
    default: return "(unknown)"; break;
    }
}

const char*
getWSAErrorString(
    DWORD Status
)
{
    switch(Status)
    {
    case WSAEINTR: return "WSAEINTR : WSACancelBlockingCall"; break;
    case WSAENETRESET: return "WSAENETRESET"; break;
    case WSAECONNABORTED: return "WSAECONNABORTED"; break;
    case WSAECONNRESET: return "WSAECONNRESET"; break;
    case WSAEISCONN: return "WSAEISCONN"; break;
    default: return "(unknown)"; break;
    }
}

void
DisplayCertChain(
    PCCERT_CONTEXT Cert,
    BOOL fLocal,
    FILE* out
)
{
    CHAR szName[1000];
    PCCERT_CONTEXT pCurrentCert;
    PCCERT_CONTEXT pIssuerCert;
    DWORD dwVerificationFlags;

    fprintf(out, "\n");

    // display leaf name
    if ( !CertNameToStr(Cert->dwCertEncodingType,
                        &Cert->pCertInfo->Subject,
                        CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
                        szName, sizeof(szName)) )
    {
        fprintf(out, "ERROR (0x%x): building subject name\n", GetLastError());
    }
    if ( fLocal )
    {
        fprintf(out, "Client subject: %s\n", szName);
    }
    else
    {
        fprintf(out, "Server subject: %s\n", szName);
    }
    if ( !CertNameToStr(Cert->dwCertEncodingType,
                        &Cert->pCertInfo->Issuer,
                        CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
                        szName, sizeof(szName)))
    {
        fprintf(out, "ERROR (0x%x): building issuer name\n", GetLastError());
    }
    if ( fLocal )
    {
        fprintf(out, "Client issuer: %s\n", szName);
    }
    else
    {
        fprintf(out, "Server issuer: %s\n\n", szName);
    }


    // display certificate chain
    pCurrentCert = Cert;
    while ( pCurrentCert != NULL )
    {
        dwVerificationFlags = 0;
        pIssuerCert = CertGetIssuerCertificateFromStore(Cert->hCertStore,
                                                        pCurrentCert,
                                                        NULL,
                                                        &dwVerificationFlags);
        if ( pIssuerCert == NULL )
        {
            if ( pCurrentCert != Cert )
            {
                CertFreeCertificateContext(pCurrentCert);
            }
            break;
        }

        if ( !CertNameToStr(pIssuerCert->dwCertEncodingType,
                            &pIssuerCert->pCertInfo->Subject,
                            CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
                            szName, sizeof(szName)))
        {
            fprintf(out, "ERROR (0x%x): building subject name\n", GetLastError());
        }
        fprintf(out, "CA subject: %s\n", szName);
        if ( !CertNameToStr(pIssuerCert->dwCertEncodingType,
                          &pIssuerCert->pCertInfo->Issuer,
                          CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
                          szName, sizeof(szName)) )
        {
            fprintf(out, "ERROR (0x%x): building issuer name\n", GetLastError());
        }
        fprintf(out, "CA issuer: %s\n\n", szName);

        if ( pCurrentCert != Cert )
        {
            CertFreeCertificateContext(pCurrentCert);
        }
        pCurrentCert = pIssuerCert;
        pIssuerCert = NULL;
    }
}

void
DisplayConnectionInfo(
    CtxtHandle *phContext,
    PSecurityFunctionTable SSPI,
    FILE* out
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
        return;
    }

    fprintf(out, "\n");

    fprintf(out, "Protocol: ");
    switch ( ConnectionInfo.dwProtocol )
    {
        case SP_PROT_TLS1_0_CLIENT:
            fprintf(out, "TLS1.0 Client\n");
            break;

        case SP_PROT_TLS1_0_SERVER:
            fprintf(out, "TLS1.0 Server\n");
            break;

        case SP_PROT_TLS1_1_CLIENT:
            fprintf(out, "TLS1.1 Client\n");
            break;

        case SP_PROT_TLS1_1_SERVER:
            fprintf(out, "TLS1.1 Server\n");
            break;

        case SP_PROT_TLS1_2_CLIENT:
            fprintf(out, "TLS1.2 Client\n");
            break;

        case SP_PROT_TLS1_2_SERVER:
            fprintf(out, "TLS1.2 Server\n");
            break;

        case SP_PROT_TLS1_3_CLIENT:
            fprintf(out, "TLS1.3 Client\n");
            break;

        case SP_PROT_TLS1_3_SERVER:
            fprintf(out, "TLS1.3 Server\n");
            break;

        case SP_PROT_SSL3_CLIENT:
            fprintf(out, "SSL3 Client\n");
            break;

        case SP_PROT_PCT1_CLIENT:
            fprintf(out, "PCT Client\n");
            break;

        case SP_PROT_SSL2_CLIENT:
            fprintf(out, "SSL2 Client\n");
            break;

        default:
            fprintf(out, "0x%x\n", ConnectionInfo.dwProtocol);
    }

    switch ( ConnectionInfo.aiCipher )
    {
        case CALG_AES_128: 
            fprintf(out, "Cipher: AES 128-bit\n");
            break;

        case CALG_AES_256: 
            fprintf(out, "Cipher: AES 256-bit\n");
            break;

        case CALG_RC4: 
            fprintf(out, "Cipher: RC4\n");
            break;

        case CALG_3DES: 
            fprintf(out, "Cipher: Triple DES\n");
            break;

        case CALG_RC2: 
            fprintf(out, "Cipher: RC2\n");
            break;

        case CALG_DES: 
        case CALG_CYLINK_MEK:
            fprintf(out, "Cipher: DES\n");
            break;

        case CALG_SKIPJACK: 
            fprintf(out, "Cipher: Skipjack\n");
            break;

        case 0: 
            fprintf(out, "Cipher: no cipher\n");
            break;

        default: 
            fprintf(out, "Cipher: 0x%x\n", ConnectionInfo.aiCipher);
    }

    fprintf(out, "Cipher strength: %d\n", ConnectionInfo.dwCipherStrength);

    switch(ConnectionInfo.aiHash)
    {
        case CALG_MD5: 
            fprintf(out, "Hash: MD5\n");
            break;

        case CALG_SHA: 
            fprintf(out, "Hash: SHA\n");
            break;

        case CALG_SHA_256: 
            fprintf(out, "Hash: SHA 256\n");
            break;
            
        case CALG_SHA_384: 
            fprintf(out, "Hash: SHA 384\n");
            break;
            
        case CALG_SHA_512: 
            fprintf(out, "Hash: SHA 512\n");
            break;

        default: 
            fprintf(out, "Hash: 0x%x\n", ConnectionInfo.aiHash);
    }

    fprintf(out, "Hash strength: %d\n", ConnectionInfo.dwHashStrength);

    switch ( ConnectionInfo.aiExch )
    {
        case CALG_RSA_KEYX: 
        case CALG_RSA_SIGN: 
            fprintf(out, "Key exchange: RSA\n");
            break;

        case CALG_KEA_KEYX: 
            fprintf(out, "Key exchange: KEA\n");
            break;
            
        case CALG_DH_SF:
            fprintf(out, "Key exchange: DH SF\n");
            break;

        case CALG_DH_EPHEM:
            fprintf(out, "Key exchange: DH Ephemeral\n");
            break;
            
        case CALG_AGREEDKEY_ANY:
            fprintf(out, "Key exchange: AGREEDKEY_ANY\n");
            break;
            
        case CALG_HUGHES_MD5:
            fprintf(out, "Key exchange: HUGHES_MD5\n");
            break;
            
        case CALG_ECDH:
            fprintf(out, "Key exchange: ECDH\n");
            break;
            
        case CALG_ECDH_EPHEM:
            fprintf(out, "Key exchange: ECDH Ephemeral\n");
            break;
            
        case CALG_ECMQV:
            fprintf(out, "Key exchange: ECMQV\n");
            break;
            
        case CALG_THIRDPARTY_KEY_EXCHANGE:
            fprintf(out, "Key exchange: THIRDPARTY_KEY_EXCHANGE\n");
            break;

        default: 
            fprintf(out, "Key exchange: 0x%x\n", ConnectionInfo.aiExch);
    }

    fprintf(out, "Key exchange strength: %d\n", ConnectionInfo.dwExchStrength);
}



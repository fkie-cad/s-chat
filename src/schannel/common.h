#ifndef COMMON_H
#define COMMON_H

#include <windows.h>
#include "sec.h"
#include <stdio.h>

#include "../utils/Logger.h"
extern size_t loggerId;
extern Logger logger;

/**
 * Print bytes array
 * 
 * @param buffer PVOID the bytes array
 * @param n ULONG length of aary
 * @param bs INT block size to format in lines of block size bytes. 0 for no block breaking.
 * @param prefix char* Prefix to insert before each bock
 */
void
printBytes(
    PVOID buffer, 
    ULONG n, 
    INT bs,
    const char* prefix
);

/**
 * Print bytes array in reverse order
 * 
 * @param buffer PVOID the bytes array
 * @param n ULONG length of aary
 * @param bs INT block size to format in lines of block size bytes. 0 for no block breaking.
 * @param prefix char* Prefix to insert before each bock
 */
void
printReverseBytes(
    PVOID buffer, 
    ULONG n, 
    INT bs,
    const char* prefix
);

void printSecPackages();

void printSecPkgInfo(
    PSecPkgInfo info
);

void
printCert(
    PCCERT_CONTEXT cert
);

int
saveCert(
    PCCERT_CONTEXT cert,
    const char* label,
    const char* dir
);

void
PrintHexDump(
    DWORD length, 
    PVOID buffer
);

const char*
GetWinVerifyTrustError(
    DWORD Status
);

const char*
getSecErrorString(
    DWORD Status
);

const char*
getWSAErrorString(
    DWORD Status
);

void
DisplayCertChain(
    PCCERT_CONTEXT  pServerCert,
    BOOL            fLocal
);

void
DisplayConnectionInfo(
    CtxtHandle *phContext,
    PSecurityFunctionTable SSPI
);

#endif 

#ifndef COMMON_H
#define COMMON_H

#include <windows.h>
#include "sec.h"
#include <stdio.h>

/**
 * Print bytes array
 * 
 * @param buffer PVOID the bytes array
 * @param n ULONG length of aary
 * @param bs INT block size to format in lines of block size bytes. 0 for no block breaking.
 * @param prefix char* Prefix to insert before each bock
 * @param out FILE* out FILE stream
 */
void
printBytes(
    PVOID buffer, 
    ULONG n, 
    INT bs,
    const char* prefix,
    FILE* out
);

/**
 * Print bytes array in reverse order
 * 
 * @param buffer PVOID the bytes array
 * @param n ULONG length of aary
 * @param bs INT block size to format in lines of block size bytes. 0 for no block breaking.
 * @param prefix char* Prefix to insert before each bock
 * @param out FILE* out FILE stream
 */
void
printReverseBytes(
    PVOID buffer, 
    ULONG n, 
    INT bs,
    const char* prefix,
    FILE* out
);

void printSecPackages(
    FILE* out
);

void printSecPkgInfo(
    PSecPkgInfo info, 
    FILE* out
);

void
printCert(
    PCCERT_CONTEXT cert,
    FILE* out
);

int
saveCert(
    PCCERT_CONTEXT cert,
    const char* label,
    const char* dir,
    FILE* out
);

void
PrintHexDump(
    DWORD length, 
    PVOID buffer,
    FILE* out
);

void
DisplayWinVerifyTrustError(
    DWORD Status,
    FILE* out
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
    BOOL            fLocal,
    FILE* out
);

void
DisplayConnectionInfo(
    CtxtHandle *phContext,
    PSecurityFunctionTable SSPI,
    FILE* out
);

#endif 

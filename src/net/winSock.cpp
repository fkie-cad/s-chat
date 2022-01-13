#include <stdio.h>

#include "../dbg.h"
#include "winSock.h"


int initS()
{
    WSADATA wsa;
#ifdef DEBUG_PRINT
    printf("\nInitialising Winsock... ");
#endif
    if ( WSAStartup(MAKEWORD(2,2),&wsa) != 0 )
    {
        logger.logError(loggerId, WSAGetLastError(), "WSAStartup failed\n");
        return GetLastError();
    }
#ifdef DEBUG_PRINT
    logger.logInfo(loggerId, 0, " wVersion: 0x%04x\n", wsa.wVersion);
    logger.logInfo(loggerId, 0, " wHighVersion: 0x%04x\n", wsa.wHighVersion);
    logger.logInfo(loggerId, 0, " iMaxSockets: 0x%x\n", wsa.iMaxSockets);
    logger.logInfo(loggerId, 0, " iMaxUdpDg: 0x%x\n", wsa.iMaxUdpDg);
    logger.logInfo(loggerId, 0, " lpVendorInfo: %p\n", (PVOID)wsa.lpVendorInfo); // should be ignored
    logger.logInfo(loggerId, 0, " szDescription: %.*s\n", WSADESCRIPTION_LEN, wsa.szDescription);
    logger.logInfo(loggerId, 0, " szSystemStatus: %.*s\n", WSASYS_STATUS_LEN, wsa.szSystemStatus);
#endif
    return 0;
}

void closeSocket(SOCKET* s)
{
    if ( !s || *s == INVALID_SOCKET )
        return;

    closesocket(*s);
    *s = INVALID_SOCKET;
}

void cleanUp(SOCKET* s)
{
    closeSocket(s);
    WSACleanup();
}

int getLastSError()
{
    return WSAGetLastError();
}

int getLastError()
{
    return GetLastError();
}

void checkReceiveError(int le)
{
    switch (le)
    {
    case WSAECONNRESET:
        printf("connection reset\n");
    case WSAECONNABORTED:
        printf("connection aborted\n");
    case WSAENOTCONN:
        printf("not connected\n");
    default:
        printf("ERROR (0x%lx): recv failed.\n", le);
    }
}

int deblockSocket(SOCKET sock)
{
    u_long mode = 0;
    int s = ioctlsocket(sock, FIONBIO, &mode);
    if ( s == SOCKET_ERROR )
    {
        logger.logError(loggerId, s, "ioctlsocket failed.\n", getLastSError());
    }

    return s;
}

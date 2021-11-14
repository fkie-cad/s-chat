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
        printf("Failed. Error Code : %d\n", WSAGetLastError());
        return -1;
    }
#ifdef DEBUG_PRINT
    printf(" wVersion: 0x%04x\n", wsa.wVersion);
    printf(" wHighVersion: 0x%04x\n", wsa.wHighVersion);
    printf(" iMaxSockets: 0x%x\n", wsa.iMaxSockets);
    printf(" iMaxUdpDg: 0x%x\n", wsa.iMaxUdpDg);
    printf(" lpVendorInfo: %p\n", (PVOID)wsa.lpVendorInfo); // should be ignored
    printf(" szDescription: %.*s\n", WSADESCRIPTION_LEN, wsa.szDescription);
    printf(" szSystemStatus: %.*s\n", WSASYS_STATUS_LEN, wsa.szSystemStatus);
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
    if (le == WSAECONNRESET)
        printf("connection reset\n");
    else if (le == WSAECONNABORTED)
        printf("connection aborted\n");
    else if (le == WSAENOTCONN)
        printf("not connected\n");
    else
        printf("ERROR (0x%lx): recv failed.\n", le);
}

int deblockSocket(SOCKET sock)
{
    u_long mode = 0;
    int s = ioctlsocket(sock, FIONBIO, &mode);
    if ( s == SOCKET_ERROR )
    {
        printf("ERROR (0x%x): ioctlsocket failed.\n", getLastSError());
    }

    return s;
}

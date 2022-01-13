#include <stdio.h>

#include "../dbg.h"
#include "sock.h"



int initConnection(
    PADDRINFOA *addr_info,
    ADDRESS_FAMILY family,
    char *ip,
    char *port_str,
    SOCKET *sock,
    int flags
)
{
    int s;

    ADDRINFOA hints;

    s = initS();
    if ( s != 0 )
        return s;
    
#ifdef DEBUG_PRINT
    logger.logInfo(loggerId, 0, "Initialized.\n");
#endif

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = flags;

    // Resolve the server address and port
#ifdef DEBUG_PRINT
    logger.logInfo(loggerId, 0, "getaddrinfo\n");
#endif
    s = getaddrinfo(ip, port_str, &hints, addr_info);
    if ( s != 0 || (*addr_info)->ai_addr == NULL)
    {
#ifdef DEBUG_PRINT
        logger.logError(loggerId, s, "failed with error\n");
#endif
        //s = -1;
        goto clean;
    }
#ifdef DEBUG_PRINT
    printAddrInfo(*addr_info);
#endif

    //Create a socket
    *sock = socket((*addr_info)->ai_family, (*addr_info)->ai_socktype, (*addr_info)->ai_protocol);
    if ( *sock == INVALID_SOCKET )
    {
        s = getLastSError();
#ifdef DEBUG_PRINT
        logger.logError(loggerId, s, "Could not create socket.\n");
#endif
        goto clean;
    }
    
#ifdef DEBUG_PRINT
    logger.logInfo(loggerId, 0, "Socket created.\n");
#endif
    
clean:
    ;

    return s;
}

int connectSock(
    SOCKET sock, 
    PADDRINFOA addr_info
)
{
    int s;
    //Connect to remote server
    s = connect(sock , addr_info->ai_addr, (int)addr_info->ai_addrlen);
    if ( s < 0)
    {
        return getLastSError();
    }
    return 0;
}

void printAddrInfo(
    ADDRINFOA *info
)
{
    logger.logInfo(loggerId, 0, " - ai_flags: %d\n", info->ai_flags);
    logger.logInfo(loggerId, 0, " - ai_family: %d\n", info->ai_family);
    logger.logInfo(loggerId, 0, " - ai_socktype: %d\n", info->ai_socktype);
    logger.logInfo(loggerId, 0, " - ai_protocol: %d\n", info->ai_protocol);
#ifdef _WIN32
    logger.logInfo(loggerId, 0, " - ai_addrlen: 0x%zx\n", info->ai_addrlen);
#else
    logger.logInfo(loggerId, 0, " - ai_addrlen: 0x%x\n", info->ai_addrlen);
#endif
    logger.logInfo(loggerId, 0, " - ai_canonname: %s\n", info->ai_canonname);
    logger.logInfo(loggerId, 0, " - ai_addr: 0x%p\n", (void*)info->ai_addr);
    if ( info->ai_addr )
    {
        printSockAddr((PSOCKADDR_STORAGE)info->ai_addr, (int)info->ai_addrlen);
    }
    while ( info->ai_next )
        printAddrInfo(info->ai_next);
}

void printSockAddr(
    PSOCKADDR_STORAGE addr, 
    int addr_ln
)
{
    int i;
    PSOCKADDR addr4 = NULL;
    PSOCKADDR_IN6 addr6 = NULL;
    uint16_t port;

    //logger.logInfo(loggerId, 0, " - addr_ln: 0x%x\n", addr_ln);
    //uint8_t* a = (uint8_t*)addr;
    //for ( i=0; i<addr_ln; i++ )
    //    logger.logInfo(loggerId, 0, "%02x ", a[i]);
    //logger.logInfo(loggerId, 0, "\n");

    logger.logInfo(loggerId, 0, " - sa_family: 0x%x\n", addr->ss_family);
    if ( addr->ss_family == AF_INET )
    {
        if ( addr_ln < sizeof(SOCKADDR) )
            return;
        addr4 = (PSOCKADDR)addr;
        port = ntohs( MAKE_UINT16(&addr4->sa_data[0]) );
        logger.logInfo(loggerId, 0, " - port: 0x%x (%u)\n", port, port);
        logger.logInfo(loggerId, 0, " - ip: ");
        logger.logInfo(loggerId, 0, "%u", (uint8_t)addr4->sa_data[2]);
        for ( i=3; i<6; i++ )
            logger.logInfo(loggerId, 0, ".%u", (uint8_t)addr4->sa_data[i]);
        logger.logInfo(loggerId, 0, "\n");
    }
    else
    {
        if ( addr_ln < sizeof(SOCKADDR_IN6) )
            return;
        addr6 = (PSOCKADDR_IN6)addr;
        logger.logInfo(loggerId, 0, " - port: 0x%x (%u)\n", ntohs(addr6->sin6_port), ntohs(addr6->sin6_port));
        logger.logInfo(loggerId, 0, " - flowinfo: 0x%x\n", addr6->sin6_flowinfo);
#ifdef _WIN32
        logger.logInfo(loggerId, 0, " - ip: %x", ntohs(addr6->sin6_addr.u.Word[0]));
        for ( i=1; i<8; i++ )
            logger.logInfo(loggerId, 0, ":%x", ntohs(addr6->sin6_addr.u.Word[i]));
        logger.logInfo(loggerId, 0, "\n");
#else
        logger.logInfo(loggerId, 0, " - ip: %x", ntohs(addr6->sin6_addr.s6_addr16[0]));
        for ( i=1; i<8; i++ )
            logger.logInfo(loggerId, 0, ":%x", ntohs(addr6->sin6_addr.s6_addr16[i]));
        logger.logInfo(loggerId, 0, "\n");
#endif
        logger.logInfo(loggerId, 0, " - flowinfo: 0x%x\n", addr6->sin6_scope_id);
#if defined(_WIN32) && !defined(WDK7600)
        logger.logInfo(loggerId, 0, " - scope.zone: 0x%x\n", addr6->sin6_scope_struct.Zone);
        logger.logInfo(loggerId, 0, " - scope.Level: 0x%x\n", addr6->sin6_scope_struct.Level);
#endif
        logger.logInfo(loggerId, 0, "\n");
    }
}


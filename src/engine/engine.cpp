#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN0
#endif

#include <winsock2.h> // before windows.h !!!
#include <windows.h>
#include <WINIOCTL.H>
#include <Ws2tcpip.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <mutex>
#include <string>

FILE* out = NULL;
FILE* log_out = NULL;

#include "../dbg.h"
#include "../version.h"
#include "../crypto/windows/HasherCNG.h"
#include "../net/sock.h"
#include "engine.h"
#include "../schannel/common.h"
#include "../schannel/TlsSock.h"
#include "../crypto/windows/HasherCNG.h"
#include "../files/Files.h"
#include "filetransfer.h"
#include "MessageHandler.h"



static SOCKET ConnectSocket = INVALID_SOCKET;
SOCKET ListenSocket = INVALID_SOCKET;

char* target_ip = NULL;
//static char* connected_ip = NULL;
//static char* connected_port = NULL;
char* target_port = NULL;
ADDRESS_FAMILY family = AF_UNSPEC;
const char* nick = NULL;
char other_name[MAX_NAME_LN];
uint8_t other_cert_hash[SHA256_BYTES_LN];
static int engine_type = ENGINE_TYPE_NONE;
static const char* log_dir = NULL;
const char* cert_dir = NULL;
const char* file_dir = NULL;

int last_type = 0;

static UCHAR gBuffer[IO_BUFFER_SIZE];

FT_SEND_OBJECTS ft_send_obj;
FT_RECV_OBJECTS ft_recv_obj;
std::mutex ft_send_mtx; // initialization problem, when in FT_SOBJECTS

PSecurityFunctionTable g_pSSPI;

// certs will contain a handle to it
HCERTSTORE hMyCertStore = NULL; 
//BOOL fContextInitialized = false; //
CredHandle hClientCreds; //
CredHandle hServerCreds;
CtxtHandle hContext; //
//BOOL cCredsInitialized = false;
//BOOL sCredsInitialized = false; //

SecPkgContext_StreamSizes Sizes; //
PBYTE SendBuffer = NULL;
ULONG SendBufferSize = 0;
PBYTE ReceiveBuffer = NULL;
ULONG ReceiveBufferSize = 0;

BOOL fClientAuth = true;

static BOOL wsaStarted = false;
static BOOL logInitialized = false;
static BOOL receiving = false;
static BOOL listening = false;

#ifdef GUI
#include "../guiBridge.h"
#endif



void closeLog();
int handleConnection(char* msg, uint32_t msg_len);
int sendMessages(char* buffer, uint32_t size);

ULONG sendDataThread(LPVOID lpParam);
int cleanFtSendConnection(
    SOCKET* Socket,
    PCtxtHandle Context,
    int Type
);

void initObjects();
void initFTObject(PFT_OBJECTS obj);

#ifndef GUI
/**
 * For standanlone test builds without gui.
 */
int main(int argc, char** argv)
{
    out = stdout;
    fprintf(out, "%s\n", REL_NAME);
    fprintf(out, "Version: %s - %s\n", REL_VS, REL_DATE);
    fprintf(out, "Compiled: %s -- %s\n\n", COMPILE_DATA, COMPILE_TIME);

    if ( argc < 6 )
    {
        fprintf(out, "usage: %s ip port type certName [nickname]\n\n", argv[0]);
        fprintf(out, "ip: server/client ip\n");
        fprintf(out, "port: server port\n");
        fprintf(out, "ipv: ip version 4 or 6\n");
        fprintf(out, "type: 1: sending client, 2: receiving client, 3: sending server, 4: receiving server\n");
        fprintf(out, "certName: Name of cert in cert store\n");
        fprintf(out, "nickname: Nickname\n");
        return EXIT_FAILURE;
    }
    
    target_ip = argv[1];
    target_port = argv[2];
    char* ipv = (int)strtoul(argv[3], NULL, 0);
    if ( ipv == 4 )
        family = AF_INET;
    else if ( ipv == 6 )
        family = AF_INET6;
    else 
        family = AF_INET;
    int type = strtol(argv[4], NULL, 0);
    char* cert_name = argv[5];
    if ( argc > 6 )
        nick = argv[6];
    else
        nick = "Nick";

    if ( strlen(nick) > MAX_NAME_LN )
    {
        fprintf(out, "Nick to long!\n");
        return -1;
    }
    
    int s = -1;

    if ( type == 1 || type == 2 )
    {
        s = initClient(target_ip, target_port, family, cert_name);
    }
    else if ( type == 3 || type == 4 )
    {
        s = initServer(target_ip, target_port, family, cert_name);

        CHAR msg[MESSAGE_SIZE];
        ULONG msg_len = MESSAGE_SIZE;
        client_handleConnections(msg, msg_len);
    }
    
    if ( s != 0 )
    {
        fprintf(out, "Init failed!\n");
        return -1;
    }

    fprintf(out, "ip: %s\n", ip);
    fprintf(out, "port: %s\n", port);
    fprintf(out, "nick: %s\n", nick);

    char buffer[MESSAGE_SIZE];

    if ( type == 1 )
    {
        sendMessages(buffer, MESSAGE_SIZE);
    }
    else if ( type == 2 )
    {
        ZeroMemory(buffer, MESSAGE_SIZE);
        receiveMessages(buffer, MESSAGE_SIZE);
    }
    //else if ( type == 3 )
    //{
    //    ZeroMemory(buffer, MESSAGE_SIZE);
    //    receiveMessages(buffer, MESSAGE_SIZE);
    //}

    return 0;
}
#endif

void initObjects()
{
    ZeroMemory(&hContext, sizeof(hContext));
    ZeroMemory(&hClientCreds, sizeof(hClientCreds));
    ZeroMemory(&hServerCreds, sizeof(hServerCreds));
    initFTObject(&ft_send_obj);
    initFTObject(&ft_recv_obj);
}

int initClient(
    char* ip, 
    char* port,
    ADDRESS_FAMILY family_,
    char* cert_name
)
{
    int s = 0;
    PADDRINFOA addr_info = NULL;
    u_long iMode = 1;
    target_ip = ip;
    target_port = port;
    family = family_;

    initLog("client");
#ifdef DEBUG_PRINT
    fprintf(out, "initClient\n");
    fprintf(out, " - ip: %s\n", ip);
    fprintf(out, " - port: %s\n", port);
    fprintf(out, " - family: %u\n", family);
    fprintf(out, " - cert: %s\n", cert_name);
    //fprintf(out, " - dp level: %u\n", DEBUG_PRINT);
#endif

    if ( ip == NULL || strlen(ip) == 0 )
    {
        s = SCHAT_ERROR_NO_IP;
        fprintf(out, "ERROR (0x%x): No ip!\n", s);
        return s;
    }

    if ( family != AF_INET && family != AF_INET6 )
    {
        s = SCHAT_ERROR_WRONG_IPV;
        fprintf(out, "ERROR (0x%x): Wrong ip version!\n", s);
        return s;
    }

    if ( port == NULL || strlen(port) == 0 )
    {
        s = SCHAT_ERROR_NO_PORT;
        fprintf(out, "ERROR (0x%x): No port!\n", s);
        return s;
    }

    if ( cert_name == NULL || strlen(cert_name) == 0 )
    {
        s = SCHAT_ERROR_NO_CERT;
        fprintf(out, "ERROR (0x%x): No cert name!\n", s);
        return s;
    }

    initObjects();
    
    if ( !initSecurityInterface() )
    {
        fprintf(out, "ERROR initializing the security library\n");
        s = SCHAT_ERROR_INIT_SEC_INTERFACE;
        goto clean;
    }

    //printSecPackages(out);

    s = CreateCredentials(
            cert_name, 
            &hClientCreds, 
            SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_MANUAL_CRED_VALIDATION | SCH_USE_STRONG_CRYPTO,
            SECPKG_CRED_OUTBOUND
    );
    if ( s != 0 )
    {
        fprintf(out, "ERROR creating credentials\n");
        s = SCHAT_ERROR_CREATE_CREDENTIALS;
        goto clean;
    }

    s = connectTLSSocket(
            ip, 
            port, 
            family, 
            &ConnectSocket, 
            &hContext, 
            &hClientCreds,
            other_cert_hash
        );
    if ( s != 0 )
        goto clean;
    wsaStarted = true;
    
#ifdef GUI
    char hash[SHA1_STRING_BUFFER_LN];
    hashToString(other_cert_hash, SHA1_BYTES_LN, hash, SHA1_STRING_BUFFER_LN);
    showCertSha(hash);
#endif

    s = readStreamEncryptionProperties(&Sizes, &hContext);
    if ( s != 0 )
    {
        fprintf(out, "ERROR (0x%x): readStreamEncryptionProperties failed!\n", s);
        s = SCHAT_ERROR_GET_SIZES;
        goto clean;
    }

    s = allocateBuffer(&Sizes, &SendBuffer, &SendBufferSize);
    if ( s != 0 )
    {
        fprintf(out, "ERROR (0x%x): allocate SendBuffer failed!\n", s);
        s = SCHAT_ERROR_NO_MEMORY;
        goto clean;
    }
    s = allocateBuffer(&Sizes, &ReceiveBuffer, &ReceiveBufferSize);
    if ( s != 0 )
    {
        fprintf(out, "ERROR (0x%x): allocate ReceiveBuffer failed!\n", s);
        s = SCHAT_ERROR_NO_MEMORY;
        goto clean;
    }

    // unblock socket
    s = ioctlsocket(ConnectSocket, FIONBIO, &iMode);
    if ( s != 0 )
    {
        fprintf(out, "ioctlsocket failed with error: 0x%x\n", getLastSError());
        s = SCHAT_ERROR_IOCTL_SOCKET;
        goto clean;
    }

    engine_type = ENGINE_TYPE_CLIENT;

clean:
    if ( addr_info != NULL )
        freeaddrinfo(addr_info);
    
    if ( s != 0 )
    {
        cleanClient();
    }

    return s;
}

int initServer(
    char* ip, 
    char* port,
    ADDRESS_FAMILY family_,
    char* cert_name
)
{
    int s = 0;
    target_ip = ip;
    target_port = port;
    family = family_;
    int iOptval = 1;
    
    PADDRINFOA addr_info = NULL;
    
    initLog("server");
#ifdef DEBUG_PRINT
    fprintf(out, "initServer\n");
    fprintf(out, " - ip: %s\n", ip);
    fprintf(out, " - port: %s\n", port);
    fprintf(out, " - family: %u\n", family);
    fprintf(out, " - cert: %s\n", cert_name);
#endif

    // may be empty for servers
    if ( ip != NULL && ip[0] == 0 )
    {
        ip = NULL;
    }

    if ( family != AF_INET && family != AF_INET6 )
    {
        s = SCHAT_ERROR_WRONG_IPV;
        fprintf(out, "ERROR (0x%x): Wrong ip version!\n", s);
        return s;
    }

    if ( port == NULL || strlen(port) == 0 )
    {
        s = SCHAT_ERROR_NO_PORT;
        fprintf(out, "ERROR (0x%x): No port!\n", s);
        return s;
    }

    if ( cert_name == NULL || strlen(cert_name) == 0 )
    {
        s = SCHAT_ERROR_NO_CERT;
        fprintf(out, "ERROR (0x%x): No cert name!\n", s);
        return s;
    }
    
    initObjects();
    
    if ( !initSecurityInterface() )
    {
        fprintf(out, "ERROR initializing the security library\n");
        s = SCHAT_ERROR_INIT_SEC_INTERFACE;
        goto clean;
    }

    // Create credentials.
    s = CreateCredentials(
        cert_name, 
        &hServerCreds, 
        SCH_USE_STRONG_CRYPTO, 
        SECPKG_CRED_INBOUND
    );
    if ( s != 0 )
    {
        fprintf(out, "ERROR creating credentials\n");
        s = SCHAT_ERROR_CREATE_CREDENTIALS;
        goto clean;
    }
    //sCredsInitialized = true;

#ifdef DEBUG_PRINT
    fprintf(out, "initConnection\n");
#endif
    s = initConnection(&addr_info, family, ip, port, &ListenSocket, AI_PASSIVE, out);
    if ( s != 0 )
    {
        fprintf(out, "initConnection failed with error: 0x%x\n", s);
        s = SCHAT_ERROR_INIT_CONNECTION;
        goto clean;
    }
    wsaStarted = true;
    
#ifdef DEBUG_PRINT
    fprintf(out, "connection initialized\n");
#endif
    
    s = setsockopt(ListenSocket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char*)&iOptval, sizeof(iOptval));
    if ( s == SOCKET_ERROR)
    {
        printf("setsockopt for SO_EXCLUSIVEADDRUSE failed with error: 0x%x\n", WSAGetLastError());
        return -1;
    }

#ifdef DEBUG_PRINT
    fprintf(out, "bind\n");
#endif
    // Setup the TCP listening socket
    errno = 0;
    s = bind(ListenSocket, addr_info->ai_addr, (int)addr_info->ai_addrlen);
    if ( s == SOCKET_ERROR )
    {
        fprintf(out, "bind failed with error: 0x%x\n", getLastSError());
        s = SCHAT_ERROR_BIND;
        goto clean;
    }
#ifdef DEBUG_PRINT
    fprintf(out, "socket bound\n");
#endif

    freeaddrinfo(addr_info);
    addr_info = NULL;

    errno = 0;
    s = listen(ListenSocket, MAX_CONN);
    if ( s == SOCKET_ERROR )
    {
        fprintf(out, "listen failed with error: %d\n", getLastSError());
        s = SCHAT_ERROR_LISTEN;
        goto clean;
    }
#ifdef DEBUG_PRINT
    fprintf(out, "listening\n");
#endif

    engine_type = ENGINE_TYPE_SERVER;

clean:
    if ( addr_info != NULL )
        freeaddrinfo(addr_info);
    
    if ( s != 0 )
    {
        cleanClient();
    }

    return s;
}

int client_handleConnections(char* msg, uint32_t msg_len)
{
    int s = 0;
    listening = true;
    while ( listening )
    {
        s = handleConnection(msg, msg_len);
        fprintf(out, "\n\n");
    }

    return s;
}

int handleConnection(
    char* msg, 
    uint32_t msg_len
)
{
    int s = 0;
    u_long iMode = 1;
    SOCKADDR_STORAGE raddr;
    socklen_t raddr_ln;
    
    s = acceptTLSSocket(
            ListenSocket, 
            &ConnectSocket, 
            &hContext, 
            &hServerCreds, 
            gBuffer, 
            sizeof(gBuffer),
            other_cert_hash,
            &raddr,
            &raddr_ln
        );
    if ( s != 0 )
        goto clean;
    
#ifdef GUI
    char hash[SHA1_STRING_BUFFER_LN];
    hashToString(other_cert_hash, SHA1_BYTES_LN, hash, SHA1_STRING_BUFFER_LN);
    showCertSha(hash);
#endif

    s = readStreamEncryptionProperties(&Sizes, &hContext);
    if ( s != 0 )
    {
        fprintf(out, "ERROR (0x%x): readStreamEncryptionProperties failed!\n", s);
        s = SCHAT_ERROR_GET_SIZES;
        goto clean;
    }

    s = allocateBuffer(&Sizes, &SendBuffer, &SendBufferSize);
    if ( s != 0 )
    {
        fprintf(out, "ERROR (0x%x): allocate SendBuffer failed!\n", s);
        s = SCHAT_ERROR_NO_MEMORY;
        goto clean;
    }
    s = allocateBuffer(&Sizes, &ReceiveBuffer, &ReceiveBufferSize);
    if ( s != 0 )
    {
        fprintf(out, "ERROR (0x%x): allocate ReceiveBuffer failed!\n", s);
        s = SCHAT_ERROR_NO_MEMORY;
        goto clean;
    }

    // unblock socket
    s = ioctlsocket(ConnectSocket, FIONBIO, &iMode);
    if ( s != 0 )
    {
        fprintf(out, "ERROR (0x%x): ioctlsocket failed\n", getLastSError());
        s = SCHAT_ERROR_IOCTL_SOCKET;
        goto clean;
    }

#ifdef GUI
    showConnStatus("Connected");
    changeIcon(CONNECTION_STATUS::CONNECTED);
#endif

    // Receive until interrupted
    s = receiveMessages(
            msg, 
            msg_len,
            &raddr,
            raddr_ln
        );
#ifdef GUI
    showConnStatus("Disonnected");
    if ( listening )
        changeIcon(CONNECTION_STATUS::LISTENING);
#endif
    if ( s != 0 )
    {
        fprintf(out, "ERROR (0x%x): receiveMessages failed\n", getLastSError());
        s = SCHAT_ERROR_RECEIVE_MESSAGES;
        goto clean;
    }

clean:
    client_cancelFileTransfer();

    s = Disconnect(&ConnectSocket, &hServerCreds, &hContext, ENGINE_TYPE_SERVER);

    if ( s != SEC_E_OK )
    {
        fprintf(out, "ERROR (0x%x): Disconnecting from client\n", s);
    }
    
    // closed by Disconect for sure
    //closeSocket(&ConnectSocket);

    if ( SendBuffer != NULL )
        HeapFree(GetProcessHeap(), 0, SendBuffer);
    SendBuffer = NULL;

    if ( ReceiveBuffer != NULL )
        HeapFree(GetProcessHeap(), 0, ReceiveBuffer);
    ReceiveBuffer = NULL;

    last_type = 0;

//#ifdef GUI
//    showCertSha("");
//#endif

    return s;
}

int receiveMessages(
    char* msg, 
    uint32_t len,
    SOCKADDR_STORAGE* raddr,
    socklen_t raddr_ln
)
{
    (void)msg;
    (void)len;
    int s = 0;
    SYSTEMTIME sts;
    GetLocalTime(&sts);
    fprintf(
        out, 
        "receive started: %02d.%02d.%04d %02d:%02d:%02d\n---------------------------------------\n",
        sts.wDay, sts.wMonth, sts.wYear, 
        sts.wHour, sts.wMinute, sts.wSecond
    );
    
    char header[0x100];
    int offset = 0;
#ifdef GUI
    if ( raddr_ln > 0)
    {
        PSOCKADDR addr4 = NULL;
        PSOCKADDR_IN6 addr6 = NULL;
        uint16_t port;
        if ( raddr->ss_family == AF_INET && raddr_ln >= sizeof(SOCKADDR) )
        {
            addr4 = (PSOCKADDR)raddr;
            port = ntohs( MAKE_UINT16(&addr4->sa_data[0]) );
            offset += sprintf_s(&header[offset], 0x100-offset, "ip: %u.%u.%u.%u\r\n", (uint8_t)addr4->sa_data[2], (uint8_t)addr4->sa_data[3], (uint8_t)addr4->sa_data[4], (uint8_t)addr4->sa_data[5]);
            offset += sprintf_s(&header[offset], 0x100-offset, "port: 0x%x (%u)\r\n", port, port);
        }
        else if ( raddr_ln >= sizeof(SOCKADDR_IN6) )
        {
            addr6 = (PSOCKADDR_IN6)raddr;
#ifdef _WIN32
            offset += sprintf_s(&header[offset], 0x100-offset, "ip: %x:%x:%x:%x:%x:%x:%x:%x\r\n", 
            ntohs(addr6->sin6_addr.u.Word[0]), ntohs(addr6->sin6_addr.u.Word[1]), ntohs(addr6->sin6_addr.u.Word[2]), ntohs(addr6->sin6_addr.u.Word[3]), ntohs(addr6->sin6_addr.u.Word[4]), ntohs(addr6->sin6_addr.u.Word[5]), ntohs(addr6->sin6_addr.u.Word[6]), ntohs(addr6->sin6_addr.u.Word[7]));
#else
            offset += sprintf_s(&header[offset], 0x100-offset, "ip: %x:%x:%x:%x:%x:%x:%x:%x\r\n", 
            ntohs(addr6->ssin6_addr.s6_addr16[0]), ntohs(addr6->ssin6_addr.s6_addr16[1]), ntohs(addr6->ssin6_addr.s6_addr16[2]), ntohs(addr6->ssin6_addr.s6_addr16[3]), ntohs(addr6->ssin6_addr.s6_addr16[4]), ntohs(addr6->ssin6_addr.s6_addr16[5]), ntohs(addr6->ssin6_addr.s6_addr16[6]), ntohs(addr6->ssin6_addr.s6_addr16[7]));
#endif
            offset += sprintf_s(&header[offset], 0x100-offset, "port: 0x%x (%u)\r\n", ntohs(addr6->sin6_port), ntohs(addr6->sin6_port));
        }
    }
    sprintf_s(&header[offset], 0x100-offset, "connected\r\n--------------------- %02d.%02d.%04d %02d:%02d:%02d --------------------------\r\n\r\n", 
        sts.wDay, sts.wMonth, sts.wYear, sts.wHour, sts.wMinute, sts.wSecond);
    header[0x100-1] = 0;
    showMessages(header, MSG_TYPE_INFO);
#endif

    if ( engine_type == ENGINE_TYPE_NONE )
    {
        fprintf(out, "Not initialized yet.");
        return SCHAT_ERROR_NOT_INITIALIZED;
    }

    PCredHandle creds = (engine_type == ENGINE_TYPE_CLIENT)
        ? &hClientCreds
        : &hServerCreds;
    receiving = true;
    s = receiveSChannelData(
        ConnectSocket, 
        creds, 
        &hContext, 
        &Sizes, 
        ReceiveBuffer, 
        ReceiveBufferSize,
        engine_type,
        &receiving
    );

    fprintf(out, "Receiving stopped: 0x%x\n", s);

    GetLocalTime(&sts);
    fprintf(
        out, 
        "---------------------------------------\nconnection stopped: %02d.%02d.%04d %02d:%02d:%02d\n",
        sts.wDay, sts.wMonth, sts.wYear, 
        sts.wHour, sts.wMinute, sts.wSecond
    );
#ifdef GUI
    sprintf_s(header, 0x80, "\r\n--------------------- %02d.%02d.%04d %02d:%02d:%02d --------------------------\r\ndisconnected\r\n\r\n", sts.wDay, sts.wMonth, sts.wYear, sts.wHour, sts.wMinute, sts.wSecond);
    header[0x7f] = 0;
    showMessages(header, MSG_TYPE_INFO);
#endif
    

    return s;
}

#ifndef GUI
int sendMessages(
    char* buffer, 
    uint32_t size
)
{
    int s = 0;
    while ( 1 )
    {
        ZeroMemory(buffer, size);
        
        fprintf(out, "Type a message:\n");
        fgets((char*)buffer, size, stdin);
        ULONG to_write = (ULONG)strlen((char*)buffer);
        if ( to_write >= size )
        {
            to_write = size-1;
        }
        if ( to_write > 0 && buffer[to_write-1] == '\n' )
        {
            to_write--;
        }
        if ( buffer[0] == 'q' )
        {
            fprintf(out, "Quitting!\n");
            break;
        }
        buffer[to_write] = 0;

        s = sendMessage(buffer, to_write+1);
        if ( s != 0 )
            break;
    }

    return s;
}
#endif

int client_sendMessage(
    char* msg, 
    uint32_t len
)
{
    if ( !logInitialized )
        initLog("undecided");

    if ( ConnectSocket == INVALID_SOCKET )
    {
        fprintf(out, "ConnectSocket invalid\n");
        return SCHAT_ERROR_INVALID_SOCKET;
    }
    //uint32_t max_data_size = Sizes.cbMaximumMessage - sizeof(MESSAGE_HEADER);
    uint32_t cbMessage = sizeof(SCHAT_MESSAGE_HEADER) + len;
    if ( cbMessage >= Sizes.cbMaximumMessage )
    {
        fprintf(out, "msg too big\n");
        return SCHAT_ERROR_MESSAGE_TOO_BIG;
    }
    
    PSCHAT_MESSAGE_HEADER message = (PSCHAT_MESSAGE_HEADER)(SendBuffer + Sizes.cbHeader);
    ZeroMemory(message, sizeof(SCHAT_MESSAGE_HEADER));
    message->bh.size = cbMessage;
    message->bh.type = MSG_TYPE_TEXT;
    strcpy_s(message->name, MAX_NAME_LN, nick);
    message->name[MAX_NAME_LN-1] = 0;
    memcpy(message->data, msg, len);
    message->data[len] = 0;

#ifdef GUI
    showMessages(message, true);
#endif
#ifdef DEBUG_PRINT_MESSAGE
    fprintf(out, "you: %s\n", message->data);
#endif
    int n = sendSChannelData(
        (PUCHAR)message, 
        (ULONG)message->bh.size, 
        ConnectSocket, 
        &hContext,
        &Sizes,
        SendBuffer,
        SendBufferSize
    );
    if ( n != 0 )
    {
        fprintf(out, "error sending data\n");
    }
    return n;
}


int client_sendFile(
    char* path, 
    uint32_t len,
    char* ip, 
    char* port,
    ADDRESS_FAMILY family_
)
{
    // Currently not supporting sending and receiving files at once.
    // Would be possible though with layout changes in gui.
    if ( ft_send_obj.thread_id != 0  || ft_recv_obj.thread_id != 0 )
    {
        return SCHAT_ERROR_MAX_FT;
    }

    initFTObject(&ft_send_obj);

    target_ip = ip;
    target_port = port;
    family = family_;
    
    uint32_t cbMessage = 0;
    int s = 0;

    if ( !logInitialized )
        initLog("undecided");
    
    //
    // check status

    if ( ConnectSocket == INVALID_SOCKET )
    {
        fprintf(out, "ERROR (0x%x): ConnectSocket invalid\n", SCHAT_ERROR_INVALID_SOCKET);
        return SCHAT_ERROR_INVALID_SOCKET;
    }
    
    //
    // check params

    if ( ip == NULL || strlen(ip) == 0 )
    {
        s = SCHAT_ERROR_NO_IP;
        fprintf(out, "ERROR (0x%x): No ip!\n", s);
        return s;
    }

    if ( family != AF_INET && family != AF_INET6 )
    {
        s = SCHAT_ERROR_WRONG_IPV;
        fprintf(out, "ERROR (0x%x): Wrong ip version!\n", s);
        return s;
    }

    if ( port == NULL || strlen(port) == 0 )
    {
        s = SCHAT_ERROR_NO_PORT;
        fprintf(out, "ERROR (0x%x): No port!\n", s);
        return s;
    }
    
    //
    // fill header

    if ( sizeof(SCHAT_FILE_INFO_HEADER) + len >= Sizes.cbMaximumMessage )
    {
        fprintf(out, "ERROR (0x%x): File path too long\n", SCHAT_ERROR_PATH_TOO_LONG);
        return SCHAT_ERROR_PATH_TOO_LONG;
    }

    if ( !fileExists(path) )
    {
        fprintf(out, "ERROR (0x%x): file not found!\n", SCHAT_ERROR_FILE_NOT_FOUND);
        return SCHAT_ERROR_FILE_NOT_FOUND;
    }

    size_t file_size = 0;
    s = getFileSize(path, &file_size);
    if ( s != 0 || file_size == 0 )
    {
        fprintf(out, "ERROR (0x%x): getFileSize failed or returned 0\n", SCHAT_ERROR_FILE_SIZE);
        return SCHAT_ERROR_FILE_SIZE;
    }
    
    CHAR full_path[MAX_PATH];
    CHAR* base_name = NULL;
    ULONG full_path_ln = GetFullPathNameA(path, MAX_PATH, full_path, &base_name);
    if ( full_path_ln == 0 || full_path_ln >= MAX_PATH )
    {
        fprintf(out, "ERROR (0x%x): GetFullPathName failed!\n", GetLastError());
        return SCHAT_ERROR_FILE_NOT_FOUND;
    }
    if ( base_name == NULL || base_name[0] == 0 )
    {
        fprintf(out, "ERROR (0x%x): file_name too short!\n", SCHAT_ERROR_FILE_NOT_FOUND);
        return SCHAT_ERROR_FILE_NOT_FOUND;
    }
    ULONG base_name_ln = (ULONG)strlen(base_name);
    
    uint8_t hash[SHA256_BYTES_LN];
    s = sha256File(full_path, hash, SHA256_BYTES_LN);
    if ( s != 0 )
    {
        fprintf(out, "ERROR (0x%x): Calculating hash failed!\n", s);
        return SCHAT_ERROR_CALCULATE_HASH;
    }
    
    ft_send_mtx.lock();
    ft_send_obj.running = true;
    ft_send_mtx.unlock();

    //
    // send info header to the other side

    PSCHAT_FILE_INFO_HEADER message = (PSCHAT_FILE_INFO_HEADER)(SendBuffer + Sizes.cbHeader);
    ZeroMemory(message, sizeof(SCHAT_FILE_INFO_HEADER));
    cbMessage = sizeof(SCHAT_FILE_INFO_HEADER) + base_name_ln;
    message->bh.size = cbMessage;
    message->bh.type = MSG_TYPE_FILE_INFO;
    if ( !ft_send_obj.running )
        message->bh.flags = MSG_FLAG_STOP;
    strcpy_s(message->name, MAX_NAME_LN, nick);
    message->name[MAX_NAME_LN-1] = 0;
    message->file_size = file_size;
    memcpy(message->sha256, hash, SHA256_BYTES_LN);
    message->base_name_ln = base_name_ln;
    memcpy(message->base_name, base_name, base_name_ln); // strcpy_s aborts due to wrong checks
    message->base_name[base_name_ln] = 0;

#ifdef DEBUG_PRINT
    fprintf(out, "sending\nfile_size: 0x%zx\nbase_name: %s (0x%x)\n", message->file_size, message->base_name, message->base_name_ln);
    fprintf(out, "hash: ");
    printBytes(message->sha256, SHA256_BYTES_LN, 0, "", out);
#endif

    s = sendSChannelData(
        (PUCHAR)message, 
        (ULONG)message->bh.size, 
        ConnectSocket, 
        &hContext,
        &Sizes,
        SendBuffer,
        SendBufferSize
    );
    if ( s != 0 )
    {
        fprintf(out, "error sending data\n");
        goto clean;
    }
    
    // show accepted file to send in chat
#ifdef GUI
    showSentFileInfo(
        FT_INFO_LABEL_SENDING,
        hash,
        file_size,
        base_name,
        base_name_ln,
        nick,
        true
    );
#endif

    //
    // create thread to connect/accept new socket and sending the file 

    if ( ft_send_obj.thread_id == 0 )
    {
        size_t tp_s = sizeof(FT_SEND_THREAD_DATA)+full_path_ln;
        PFT_SEND_THREAD_DATA tp = (PFT_SEND_THREAD_DATA)malloc(tp_s);
        if ( tp == NULL )
        {
            fprintf(out, "ERROR: malloc DATA_THREAD_PARAMS failed!\n");
            return SCHAT_ERROR_NO_MEMORY;
        }
        tp->file_size = file_size;
        //strcpy_s(tp->path, len, path);
        strcpy_s(tp->ip, MAX_IP_LN, ip);
        strcpy_s(tp->port, MAX_PORT_LN, port);
        tp->family = family;
        memcpy(tp->path, full_path, full_path_ln);
        tp->path[full_path_ln] = 0;
        tp->path_ln = full_path_ln;

        ft_send_obj.thread = CreateThread(
                                NULL,      // default security attributes
                                0,         // use default stack size  
                                sendDataThread,    // thread function name
                                tp,     // argument to thread function 
                                0,        // use default creation flags 
                                &ft_send_obj.thread_id    // returns the thread identifier 
                            );
        if ( ft_send_obj.thread == NULL )
        {
            s = GetLastError();
            fprintf(out, "ERROR (0x%x): CreateThread ft receive failed\n", s);
            if ( tp != NULL )
                free(tp);
            goto clean;
        }
        CloseHandle(ft_send_obj.thread);
        ft_send_obj.thread = NULL;
    }
clean:
    ;

    return s;
}

// TODO: move to filetransfer.cpp
ULONG sendDataThread(LPVOID lpParam)
{
    PFT_SEND_THREAD_DATA tp = (PFT_SEND_THREAD_DATA)(lpParam);
    int s = 0;
    size_t i;
    size_t offset;
    size_t bRead = 0;
    
    ULONG cbMessage;
    PSCHAT_FILE_DATA_HEADER message = NULL;
    uint8_t* buffer = NULL;
    ULONG buffer_size = NULL;

    ULONG block_size;
    size_t nParts;
    size_t rest;

    FILE* file = NULL;

    bool cancel_loop = false;
    BOOL running = true;

    uint8_t other_ft_cert_hash[SHA256_BYTES_LN];
    
    SOCKADDR_STORAGE raddr;
    socklen_t raddr_ln;

    PCredHandle creds = (engine_type == ENGINE_TYPE_CLIENT)
        ? &hClientCreds
        : &hServerCreds;
    
    // local connection and send buffer
    s = allocateBuffer(&Sizes, &buffer, &buffer_size);
    if ( s != 0 )
    {
        fprintf(out, "ERROR (0x%x): allocate send file buffer failed!\n", s);
        s = SCHAT_ERROR_NO_MEMORY;
        goto clean;
    }

    // A client sending a file will connect a new socket to the accepting server.
    // The accept is triggerd by the receiving FILE_INFO_HEADER.
    // The connect may appear befor the accept though.
    if ( engine_type == ENGINE_TYPE_CLIENT )
    {
        s = connectTLSSocket(
                tp->ip, 
                tp->port, 
                tp->family, 
                &ft_send_obj.Socket, 
                &ft_send_obj.Context, 
                &hClientCreds,
                other_ft_cert_hash
            );
        if ( s != 0 )
        {
            goto clean;
        }
#ifdef DEBUG_PRINT
        fprintf(out, "FT Connected\n");
#endif
    }
    // A server will (blocking) accept a new connection by the client.
    // The client connect is triggered by receiving the FILE_INFO_HEADER.
    else if ( engine_type == ENGINE_TYPE_SERVER )
    {
        s = acceptTLSSocket(
                ListenSocket, 
                &ft_send_obj.Socket, 
                &ft_send_obj.Context, 
                &hServerCreds, 
                buffer, 
                buffer_size,
                other_ft_cert_hash,
                &raddr,
                &raddr_ln
            );
        if ( s != 0 )
            goto clean;
#ifdef DEBUG_PRINT
        fprintf(out, "FT accepted\n");
#endif
    }

    // compare ft certificate hash to main connection certificate
    if ( memcmp(other_cert_hash, other_ft_cert_hash, SHA256_BYTES_LN) != 0 )
    {
        fprintf(out, "ERROR (0x%x): SCHAT_ERROR_FT_CERT_MISSMATCH\n", SCHAT_ERROR_FT_CERT_MISSMATCH);
        s = SCHAT_ERROR_FT_CERT_MISSMATCH;
        goto clean;
    }
    
    //
    // wait for accepting answer
    // This is done in new thread with ft sockets to don't block sender until receiver answers

    other_name[0] = 0;
    s = receiveSChannelData(
            ft_send_obj.Socket,
            creds,
            &ft_send_obj.Context,
            &Sizes,
            buffer, 
            buffer_size,
            engine_type,
            &running
        );
    if ( s != 0 )
    {
        fprintf(out, "ERROR (0x%x): receving ft accept answer\n", s);
        //s = SCHAT_ERROR_FT_NOT_ACCEPTED;
        goto clean;
    }


    //
    // Then the data is send over the new (accepted or connected) ft_send_obj.Socket
    // If sending is canceled, a 0 data package is sent and the cancled answer is awaited
    //
#ifdef GUI
    togglePBar(true);
    toggleFileBtn(FILE_TRANSFER_STATUS::ACTIVE);
#endif

    s = fopen_s(&file, tp->path, "rb");
    if ( s != 0 )
    {
        fprintf(out, "ERROR: file open failed!\n");
        s = SCHAT_ERROR_OPEN_FILE;
        goto clean;
    }

    block_size = Sizes.cbMaximumMessage - sizeof(SCHAT_BASE_HEADER);
    nParts = tp->file_size / block_size;
    rest = tp->file_size % block_size;
    cbMessage = Sizes.cbMaximumMessage;
    offset = 0;
#ifdef DEBUG_PRINT
    fprintf(out, "nParts: 0x%zx\n", nParts);
    fprintf(out, "block_size: 0x%x\n", block_size);
    fprintf(out, "rest: 0x%zx\n", rest);
#endif
    for ( i = 0; i < nParts; i++ )
    {
        message = (PSCHAT_FILE_DATA_HEADER)(buffer + Sizes.cbHeader);
        ZeroMemory(message, sizeof(SCHAT_FILE_DATA_HEADER));
        message->bh.type = MSG_TYPE_FILE_DATA;
        if ( !ft_send_obj.running )
        {
            message->bh.flags = MSG_FLAG_STOP;
            block_size = 0;
            cancel_loop = true;
            cbMessage = (ULONG)(sizeof(SCHAT_BASE_HEADER));
        }
        else
        {
            fseek(file, offset, SEEK_SET);
            bRead = fread(message->data, 1, block_size, file);
            if ( bRead != block_size )
            {
                fprintf(out, "ERROR (0x%x): reading data\n", GetLastError());
                s = SCHAT_ERROR_READ_FILE;
                goto clean;
            }
        }
        message->bh.size = cbMessage;

        offset += block_size;
#ifdef GUI
        showProgress(offset, tp->file_size);
#endif
        s = sendSChannelData(
                (PUCHAR)message, 
                (ULONG)message->bh.size, 
                ft_send_obj.Socket, 
                &ft_send_obj.Context,
                &Sizes,
                buffer,
                buffer_size
            );
        if ( s != 0 )
        {
            fprintf(out, "ERROR (0x%x): sending data\n", s);
            s = SCHAT_ERROR_SENDING_DATA;
            goto clean;
        }

        if ( cancel_loop )
            goto sending_finished;
    }

    if ( rest != 0 )
    {
        message = (PSCHAT_FILE_DATA_HEADER)(buffer + Sizes.cbHeader);
        ZeroMemory(message, sizeof(SCHAT_FILE_DATA_HEADER));
        message->bh.type = MSG_TYPE_FILE_DATA;
        if ( !ft_send_obj.running )
        {
            message->bh.flags = MSG_FLAG_STOP;
            rest = 0;
            cancel_loop = true;
        }
        else
        {
            fseek(file, offset, SEEK_SET);
            bRead = fread(message->data, 1, rest, file);
            if ( bRead != rest )
            {
                fprintf(out, "ERROR (0x%x): reading data\n", GetLastError());
                s = SCHAT_ERROR_READ_FILE;
                goto clean;
            }
        }

        cbMessage = (ULONG)(sizeof(SCHAT_BASE_HEADER) + rest);
        message->bh.size = cbMessage;
        
        offset += rest;
#ifdef GUI
        showProgress(offset, tp->file_size);
#endif
        s = sendSChannelData(
                (PUCHAR)message, 
                (ULONG)message->bh.size, 
                ft_send_obj.Socket, 
                &ft_send_obj.Context,
                &Sizes,
                buffer,
                buffer_size
            );
        if ( s != 0 )
        {
            fprintf(out, "ERROR (0x%x): sending data\n", s);
            s = SCHAT_ERROR_SENDING_DATA;
            goto clean;
        }

        if ( cancel_loop )
            goto sending_finished;
    }

sending_finished:
    // All data is sent or canceled.

    // Show canceld message, if so
    if ( cancel_loop )
    {
#ifdef DEBUG_PRINT
        fprintf(out, "FT Data canceled\n");
#endif
#ifdef GUI
    //const char* base_name = NULL;
    //size_t base_name_ln = getBaseName(tp->path, tp->path_ln, &base_name);
    //showSentFileInfo(
    //    FT_INFO_LABEL_CANCELED,
    //    NULL,
    //    tp->file_size,
    //    base_name,
    //    base_name_ln,
    //    nick,
    //    true
    //);
#endif
    }
    // wait for a finished reply before cleaning the connection and exiting the thread
    // If not waited, cancel finishes quicker but other side receives corrupted data.
    //else
    {
#ifdef DEBUG_PRINT
        fprintf(out, "FT Data sent, waiting for reply\n");
#endif
        ft_send_mtx.lock();
        ft_send_obj.running = true;
        ft_send_mtx.unlock();
        s = receiveSChannelData(
                ft_send_obj.Socket,
                creds,
                &ft_send_obj.Context,
                &Sizes,
                buffer,
                buffer_size,
                engine_type,
                &ft_send_obj.running
            );
        if ( s != 0 )
        {
            if ( s != SEC_I_CONTEXT_EXPIRED )
            {
                fprintf(out, "ERROR (0x%x): receving ft finished answer\n", s);
                s = SCHAT_ERROR_RECEIVE_MESSAGES;
                goto clean;
            }
        }
#ifdef DEBUG_PRINT
    fprintf(out, "FT Data received reply\n");
#endif
    }

clean:
#ifdef GUI
    if ( s == SCHAT_ERROR_SENDING_DATA )
    {
        const char* base_name = NULL;
        size_t base_name_ln = getBaseName(tp->path, tp->path_ln, &base_name);
        showSentFileInfo(
            FT_INFO_LABEL_CANCELED,
            NULL,
            tp->file_size,
            base_name,
            base_name_ln,
            other_name,
            false
        );
        s = sprintf_s((char*)buffer, buffer_size, "Filetransfer Error: 0x%x", s);
        buffer[s] = 0;
        showInfoStatus((char*)buffer);
    }

    togglePBar(false);
    toggleFileBtn(FILE_TRANSFER_STATUS::STOPPED);
#endif
    if ( file != NULL )
        fclose(file);
    if ( tp != NULL )
        free(tp);
    if ( buffer != NULL )
        HeapFree(GetProcessHeap(), 0, buffer);
    cleanFtSendConnection(&ft_send_obj.Socket, &ft_send_obj.Context, engine_type);
    ft_send_obj.thread_id = 0;
    ft_send_obj.running = false;

    return 0;
}

int cleanFtSendConnection(
    SOCKET* Socket,
    PCtxtHandle Context,
    int Type
)
{
    int s = 0;
#ifdef DEBUG_PRINT
    fprintf(out, "cleanFtSendConnection()\n");
#endif
    s = Disconnect(Socket, &hClientCreds, Context, Type);
    if ( s != 0 )
        fprintf(out, "ERROR (0x%x): disconnecting ft from server\n", s);
    else
        fprintf(out, "Disconnecting ft connection successfully\n");

    initFTObject(&ft_send_obj);

    return s;
}

int client_cancelFileTransfer()
{
    // unblock accept / connect
    // ???
    
    ft_send_mtx.lock();
    ft_send_obj.running = false;
    ft_send_mtx.unlock();

    cancelFileReceive();
    
    return 0;
};

int cleanClient()
{
    int s = 0;
    
    if ( !logInitialized )
        initLog("undecided");
    
    if ( wsaStarted  )
    {
        client_cancelFileTransfer();

        receiving = false;
        listening = false;

        s = Disconnect(&ConnectSocket, &hClientCreds, &hContext, engine_type);
        if ( s != 0 )
        {
            fprintf(out, "ERROR disconnecting from server\n");
        }
    
        // closed in Disconnect for sure
        //closeSocket(&ConnectSocket);
        closeSocket(&ListenSocket);
        closeSocket(&ft_send_obj.Socket);
        if ( wsaStarted )
            WSACleanup();
    }
    wsaStarted = false;
#ifdef DEBUG_PRINT
    fprintf(out, "cleanClient()\n");
    //fprintf(out, "ConnectSocket: 0x%zx\n", (SIZE_T)ConnectSocket);
    //fprintf(out, "ListenSocket: 0x%zx\n", (SIZE_T)ListenSocket);
#endif
    SChannel_clean(&hContext, &hClientCreds, &hServerCreds, &hMyCertStore);

    engine_type = ENGINE_TYPE_NONE;
    

    if ( SendBuffer != NULL )
        HeapFree(GetProcessHeap(), 0, SendBuffer);
    SendBuffer = NULL;

    if ( ReceiveBuffer != NULL )
        HeapFree(GetProcessHeap(), 0, ReceiveBuffer);
    ReceiveBuffer = NULL;
    
    last_type = 0;

#ifdef GUI
    closeLog();
#endif

    return EXIT_SUCCESS;
}

void initLog(const char* label)
{
    if ( logInitialized )
        return;

    out = stdout;
#ifdef GUI
    SYSTEMTIME sts;
    GetLocalTime(&sts);
    if ( log_out != NULL )
        return;
    
    const char* d = (log_dir==NULL) ? "." : log_dir;
    char out_path[MAX_PATH];
    RtlZeroMemory(out_path, MAX_PATH);
    sprintf_s(
        out_path, MAX_PATH, 
        "%s\\%s-%02d.%02d.%04d-%02d.%02d.%02d.log", 
        d,
        label,
        sts.wDay, sts.wMonth, sts.wYear, sts.wHour, sts.wMinute, sts.wSecond);
    int err = fopen_s(&log_out, out_path, "a");

    if ( !log_out || err != 0 )
    {
        fprintf(out, "Redirecting out to \"%s\" failed!\n", out_path);
        log_out = NULL;
    }
    else
    {
        out = log_out;
        setvbuf(out, NULL, _IONBF, 0);
    }
#else
    UNREFERENCED_PARAMETER(label);
#endif

    logInitialized = true;
}

void closeLog()
{
    if ( log_out != NULL )
        fclose(log_out);
    log_out = NULL;
    logInitialized = false;
}

void client_setNick(const char* nick_)
{
    nick = nick_;
}

void client_setLogDir(const char* path)
{
    log_dir = path;
}

void client_setCertDir(const char* path)
{
    cert_dir = path;
}

void client_setFileDir(const char* path)
{
    file_dir = path;
}

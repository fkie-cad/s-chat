#ifndef __ENGINE_H
#define __ENGINE_H

#include <windows.h>
#include <stdint.h>

#include "../values.h"
#include "../net/sock.h"
#include "../schannel/connection.h"


#include "../utils/Logger.h"
extern Logger logger;
extern size_t loggerId;


int initClient(
    char* ip, 
    char* port,
    ADDRESS_FAMILY family,
    char* cert_name
);

int initServer(
    char* ip, 
    char* port,
    ADDRESS_FAMILY family,
    char* cert_name
);

int client_handleConnections(
    char* msg, 
    uint32_t msg_len
);

int cleanClient();

int client_sendMessage(
    char* msg, 
    uint32_t len
);

int client_sendFile(
    char* path, 
    uint32_t len,
    char* ip, 
    char* port,
    ADDRESS_FAMILY family
);

int client_cancelFileTransfer();

int receiveMessages(
    char* msg, 
    uint32_t len,
    SOCKADDR_STORAGE* raddr,
    socklen_t raddr_ln
);

void client_setNick(
    const char* nick_
);

void client_setLogDir(
    const char* path
);

void client_setCertDir(
    const char* path
);

void client_setFileDir(
    const char* path
);

void initLog(
    const char* label
);

void showMessages(
    _In_ PSCHAT_MESSAGE_HEADER message, 
    _In_ BOOL self
);

#endif

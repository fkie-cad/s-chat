#ifndef VALUES_H
#define VALUES_H

#include <windows.h>

#include <stdint.h>
#include <stdlib.h>

#include "crypto/windows/HasherCNG.h"



#define MESSAGE_SIZE (0x1000)
#define RESPONSE_SIZE (0x1000)

#define MAX_NAME_LN (0x40)

#define ENGINE_TYPE_NONE (0)
#define ENGINE_TYPE_SERVER (1)
#define ENGINE_TYPE_CLIENT (2)
#define ENGINE_TYPE_SERVER_FT (3)
#define ENGINE_TYPE_CLIENT_FT (4)


#define MAX_IP_LN (0x28)
#define MAX_PORT_LN (0x6)


#ifndef ADDRESS_FAMILY
typedef USHORT ADDRESS_FAMILY;
#endif 


#pragma pack(1)
typedef struct _SCHAT_BASE_HEADER {
    uint64_t type; // 
    size_t size; // size of header: SCHAT_BASE_HEADER + other header
    uint32_t flags; // see MSG_FLAG_XXX
} SCHAT_BASE_HEADER, *PSCHAT_BASE_HEADER;
#pragma pack()


#pragma pack(1)
typedef struct _SCHAT_DATA_HEADER {
    uint32_t Size; // size of data
    uint32_t Offset; // offset into data
} SCHAT_DATA_HEADER, *PSCHAT_DATA_HEADER;
#pragma pack()


#pragma pack(1)
typedef struct _SCHAT_HELLO_HEADER {
    SCHAT_BASE_HEADER bh;
    SCHAT_DATA_HEADER nameHeader;
    char data[1];
} SCHAT_HELLO_HEADER, *PSCHAT_HELLO_HEADER;
#pragma pack()


#pragma pack(1)
typedef struct _SCHAT_MESSAGE_HEADER {
    SCHAT_BASE_HEADER bh;
    char name[MAX_NAME_LN];
    uint32_t data_ln;
    char data[1];
} SCHAT_MESSAGE_HEADER, *PSCHAT_MESSAGE_HEADER;
#pragma pack()


#pragma pack(1)
typedef struct _SCHAT_FILE_INFO_HEADER {
    SCHAT_BASE_HEADER bh;
    size_t file_size;
    uint8_t sha256[SHA256_BYTES_LN];
    char name[MAX_NAME_LN];
    uint32_t base_name_ln;
    char base_name[1];
} SCHAT_FILE_INFO_HEADER, *PSCHAT_FILE_INFO_HEADER;
#pragma pack()


#pragma pack(1)
typedef struct _SCHAT_FILE_STATUS_HEADER {
    SCHAT_BASE_HEADER bh;
    char name[MAX_NAME_LN];
    uint32_t base_name_ln;
    char base_name[1];
} SCHAT_FILE_STATUS_HEADER, *PSCHAT_FILE_STATUS_HEADER;
#pragma pack()


#pragma pack(1)
typedef struct _SCHAT_FILE_DATA_HEADER {
    SCHAT_BASE_HEADER bh;
    uint8_t data[1];
} SCHAT_FILE_DATA_HEADER, *PSCHAT_FILE_DATA_HEADER;
#pragma pack()


#define MSG_TYPE_HELLO (0x00000000484c4c45)
#define MSG_TYPE_TEXT (0x0000000054584554)
#define MSG_TYPE_FILE_INFO (0x00004F464E495446)
#define MSG_TYPE_FILE_DATA (0x0000415441445446)
#define MSG_TYPE_FT_STATUS (0x5355544154535446)

#define MSG_FLAG_STOP   (0x1) // stop the receiving loop after handling a message
#define MSG_FLAG_ACCEPT (0x2) // accept sth. 
#define MSG_FLAG_CANCEL (0x4) // cancel sth.



#define SCHAT_ERROR_NO_IP (0xE0000050)
#define SCHAT_ERROR_WRONG_IPV (0xE0000051)
#define SCHAT_ERROR_NO_PORT (0xE0000052)
#define SCHAT_ERROR_NO_NAME (0xE0000053)
#define SCHAT_ERROR_NO_CERT (0xE0000054)
#define SCHAT_ERROR_NO_MEMORY (0xE0000055)
#define SCHAT_ERROR_MESSAGE_TOO_BIG (0xE0000056)
#define SCHAT_ERROR_PATH_TOO_LONG (0xE0000057)
#define SCHAT_ERROR_NOT_INITIALIZED (0xE0000058)

#define SCHAT_ERROR_INIT_SEC_INTERFACE (0xE0000060)
#define SCHAT_ERROR_CREATE_CREDENTIALS (0xE0000061)
#define SCHAT_ERROR_CLIENT_HANDSHAKE (0xE0000062)
#define SCHAT_ERROR_SERVER_HANDSHAKE (0xE0000063)
#define SCHAT_ERROR_QUERY_REMOTE_CERT (0xE0000064)
#define SCHAT_ERROR_GET_SIZES (0xE0000065)
#define SCHAT_ERROR_TLS_VERSION (0xE0000066)
#define SCHAT_ERROR_OUT_OF_ORDER (0xE0000067)

#define SCHAT_ERROR_INIT_CONNECTION (0xE0000070)
#define SCHAT_ERROR_BIND (0xE0000071)
#define SCHAT_ERROR_LISTEN (0xE0000072)
#define SCHAT_ERROR_CONNECT (0xE0000073)
#define SCHAT_ERROR_IOCTL_SOCKET (0xE0000074)
#define SCHAT_ERROR_RECEIVE_MESSAGES (0xE0000075)
#define SCHAT_ERROR_INVALID_SOCKET (0xE0000076)
#define SCHAT_ERROR_SENDING_DATA (0xE0000077)
#define SCHAT_ERROR_CORRUPTED_DATA (0xE0000078)
#define SCHAT_ERROR_UNKNOWN_DATA (0xE0000079)

#define SCHAT_ERROR_FILE_SIZE (0xE0000080)
#define SCHAT_ERROR_OPEN_FILE (0xE0000081)
#define SCHAT_ERROR_FILE_NOT_FOUND (0xE0000082)
#define SCHAT_ERROR_READ_FILE (0xE0000083)
#define SCHAT_ERROR_WRITE_FILE (0xE0000084)

#define SCHAT_ERROR_CALCULATE_HASH (0xE0000090)
#define SCHAT_ERROR_SAVE_CERT (0xE0000091)

#define SCHAT_ERROR_MAX_FT (0xE00000a0)
#define SCHAT_ERROR_FT_NOT_ACCEPTED (0xE00000a1)
#define SCHAT_ERROR_FT_CANCELED (0xE00000a2)
#define SCHAT_ERROR_FT_CERT_MISSMATCH (0xE00000a3)



typedef struct _CONNECTION_DATA
{
    CHAR ip[MAX_IP_LN];
    CHAR port[MAX_PORT_LN];
    CHAR name[MAX_NAME_LN];
    CHAR CertThumb[SHA1_STRING_BUFFER_LN];
    ADDRESS_FAMILY family;
} CONNECTION_DATA, *PCONNECTION_DATA;

typedef struct _PREFERENCES_DATA
{
    CHAR LogDir[MAX_PATH];
    CHAR CertDir[MAX_PATH];
    CHAR FileDir[MAX_PATH];
} PREFERENCES_DATA, *PPREFERENCES_DATA;

typedef struct _COMFIRM_CLOSE_PARAMS {
    const char* Status;
    const char* Suggestion;
} COMFIRM_CLOSE_PARAMS, *PCOMFIRM_CLOSE_PARAMS;

#endif 

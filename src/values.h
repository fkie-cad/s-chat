#ifndef VALUES_H
#define VALUES_H

#include <windows.h>

#include <stdint.h>
#include <stdlib.h>

#include "errorCodes.h"
#include "structs.h"
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

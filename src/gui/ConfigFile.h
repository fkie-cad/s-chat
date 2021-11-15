#ifndef _CONFIG_FILE_H
#define _CONFIG_FILE_H

#include <vector>

#define CONFIG_FILE_KEY_IP (0x0)
#define CONFIG_FILE_KEY_PORT (0x1)
#define CONFIG_FILE_KEY_IP_VS (0x2)
#define CONFIG_FILE_KEY_USER_NAME (0x3)
#define CONFIG_FILE_KEY_CERT_THUMB (0x4)
#define CONFIG_FILE_KEY_LOG_FILES (0x5)
#define CONFIG_FILE_KEY_CERT_FILES (0x6)
#define CONFIG_FILE_KEY_T_FILES (0x7)

typedef struct _CONFIG_FILE
{
    char Path[MAX_PATH];
    std::vector<std::string> Keys;

    void init()
    {
        Keys = {
            "ip", 
            "port", 
            "ip version",
            "user name", 
            "user cert thumb", 
            "log files dir", 
            "cert files dir", 
            "transfered files dir"
        };
    }
} CONFIG_FILE, *PCONFIG_FILE;


#endif

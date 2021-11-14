#ifndef DBG_H
#define DBG_H

#define DEBUG_PRINT_INFO_LEVEL (0x1)
#define DEBUG_PRINT_HEX_DUMP_LEVEL (0x2)
#define DEBUG_PRINT_HEX_MSG_LEVEL (0x4)

#ifdef DEBUG_PRINT_LEVEL
    #if (((DEBUG_PRINT_LEVEL)&(DEBUG_PRINT_INFO_LEVEL))>0)
        #define DEBUG_PRINT
    #endif

    #if (((DEBUG_PRINT_LEVEL)&(DEBUG_PRINT_HEX_DUMP_LEVEL))>0)
        #define DEBUG_PRINT_HEX_DUMP
    #endif

    #if (((DEBUG_PRINT_LEVEL)&(DEBUG_PRINT_HEX_MSG_LEVEL))>0)
        #define DEBUG_PRINT_MESSAGE
    #endif
#endif

#endif

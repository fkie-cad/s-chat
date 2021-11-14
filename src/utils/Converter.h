#ifndef CONVERTER_H
#define CONVERTER_H

#include <windows.h>

#include <stdint.h>

int parsePlainBytes(
    const char* raw, 
    uint8_t** buffer, 
    uint32_t buffer_ln
);

int parseUint8(
    const char* arg, 
    uint8_t* value, 
    uint8_t base
);

int parseUint64(
    const char* arg, 
    uint64_t* value, 
    uint8_t base
);

#endif

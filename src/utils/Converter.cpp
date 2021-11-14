#include "Converter.h"

#include <stdlib.h>


#define MAX_BUFFER_LN (0x200)



int parsePlainBytes(const char* raw, uint8_t** buffer, uint32_t buffer_ln)
{
    uint32_t i, j;
    size_t raw_ln = strnlen(raw, MAX_BUFFER_LN);
    uint8_t* p;
    char byte[3] = {0};
    uint32_t size;
    int s = 0;
    
    size = (uint32_t) (raw_ln / 2);

    if ( raw == NULL || raw[0] == 0 || buffer == NULL || buffer_ln == 0 )
    {
        return -1;
    }

    if ( raw_ln >= MAX_BUFFER_LN )
    {
        //printf("Error: Raw data is too big!\n");
        return -2;
    }
    
    if ( raw_ln % 2 != 0 || raw_ln == 0 )
    {
        //printf("Error: Raw data is not byte aligned!\n");
        return -3;
    }

    if ( size != buffer_ln )
    {
        //printf("Error: Buffer data has the wrong size %u != %u!\n", size, buffer_ln);
        return -4;
    }

    if ( *buffer == NULL )
    {
        p = (uint8_t*) malloc(size);
        if ( p == NULL )
        {
            //printf("ERROR (0x%08x): Allocating memory failed!\n", GetLastError());
            return -5;
        }
    }
    else
    {
        p = *buffer;
    }

    for ( i = 0, j = 0; i < raw_ln; i += 2, j++ )
    {
        byte[0] = raw[i];
        byte[1] = raw[i + 1];

         s = parseUint8(byte, &p[j], 16);
         if ( s != 0 )
         {
             if ( *buffer == NULL )
                free(p);
            return -6;
         }
    }
    
    if ( *buffer == NULL )
    {
        *buffer = p;
    }

    return 0;
}

int parseUint8(const char* arg, uint8_t* value, uint8_t base)
{
    uint64_t result;
    int s = parseUint64(arg, &result, base);
    if ( s != 0 ) return s;
    if ( s > (uint8_t)-1 )
    {
        //fprintf(stderr, "Error: %s could not be converted to a byte: Out of range!\n", arg);
        return -1;
    }

    *value = (uint8_t) result;
    return 0;
}

int parseUint64(const char* arg, uint64_t* value, uint8_t base)
{
    char* endptr;
    int err_no = 0;
    errno = 0;
    uint64_t result;

    if ( base != 10 && base != 16 && base != 0 )
    {
        //fprintf(stderr, "Error: Unsupported base %u!\n", base);
        return -1;
    }

    if ( arg[0] ==  '-' )
    {
        //fprintf(stderr, "Error: %s could not be converted to a number: is negative!\n", arg);
        return -2;
    }

#if defined(_WIN32)
    result = strtoull(arg, &endptr, base);
#else
    result = strtoul(arg, &endptr, base);
#endif
    err_no = errno;

    if ( endptr == arg )
    {
        //fprintf(stderr, "Error: %s could not be converted to a number: Not a number!\n", arg);
        return -3;
    }
    if ( result == (uint64_t)-1 && err_no == ERANGE )
    {
        //fprintf(stderr, "Error: %s could not be converted to a number: Out of range!\n", arg);
        return -4;
    }

    *value = result;
    return 0;
}

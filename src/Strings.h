#ifndef STRINGS_H
#define STRINGS_H

bool startsWith(const char *pre, const char *str)
{
    if ( pre == NULL || str == NULL )
        return false;

    size_t lenpre = strlen(pre),
           lenstr = strlen(str);
    return lenstr < lenpre 
        ? false 
        : memcmp(pre, str, lenpre) == 0;
}

#endif

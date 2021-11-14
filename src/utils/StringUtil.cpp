//#include <windows>

// because of int to char conversion in <algorithm>
#pragma warning( disable : 4244 )

#include <string.h>

#include <algorithm>
#include <sstream>
#include <exception>

#include "StringUtil.h"



const char* StringUtil::ltrim(const char* s)
{
    size_t n = strlen(s);
    size_t i = 0;
    while ( i < n )
    {
        if ( s[i] != ' ' )
            break;
        i++;
    }
    return &s[i];
}

const char* StringUtil::rtrim(char* s)
{
    size_t n = strlen(s);
    size_t i = n - 1;
    while ( i >= 0 )
    {
        if ( s[i] != ' ' )
            break;

        if ( i > 0 )
            i--;
        else
            break;
    }
    s[i+1] = 0;
    return s;
}

const char* StringUtil::trim(char* s)
{
    return ltrim(rtrim(s));
}

int CountLines(
    uint8_t* Buffer,
    size_t BufferSize,
    uint32_t* NrLines
)
{
    int status = 0;
    char* ptr = NULL;
    uint32_t count = 0;
    ptr = (char*)Buffer;
    size_t end = (size_t)Buffer + BufferSize;

    while ( (size_t)ptr < end )
    {
        if ( *ptr == '\n' )
        {
            count++;
        }
        ptr++;
    }

    if ( Buffer[BufferSize - 1] != '\n' )
    {
        count++;
    }

    *NrLines = count;

    return status;
}

void StringUtil::split(const std::string& s, char delim, std::vector<std::string>* elems)
{
    std::stringstream ss;
    ss.str(s);
    std::string item;
    while (getline(ss, item, delim))
    {
        elems->push_back(item);
    }
}

std::vector<std::string> StringUtil::split(const std::string &s, char delim)
{
    std::vector<std::string> elems;
    split(s, delim, &elems);
    return elems;
}

bool StringUtil::toBool(std::string value)
{
    bool b = false;
    try
    {
        uint64_t v = stoul(value, nullptr, 10);
        b = (v != 0);
    }
    catch ( std::logic_error& e )
    {
        (e);
        std::transform(value.begin(), value.end(), value.begin(), ::tolower);
        std::istringstream(value) >> std::boolalpha >> b;
    }
    return b;
}


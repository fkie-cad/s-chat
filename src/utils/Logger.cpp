#include "Logger.h"

#include "StringUtil.h"

#pragma warning( disable : 4996 )

#ifndef FORMATED_TIME_STAMP_SIZE
#define FORMATED_TIME_STAMP_SIZE (0x20)
#endif

#define LOG_BUFFER_SIZE (0x200)



Logger::~Logger()
{
    clear();
}

int Logger::clear()
{
    LoggerMap::iterator it;
    for ( it = logs.begin(); it != logs.end(); ++it )
    {
#ifdef POSIX
        if ( it->second.file != NULL )
        {
            fclose(it->second.file);
        }
#else
        if ( it->second.file != NULL )
        {
            CloseHandle(it->second.file);
        }
#endif
    }
    logs.clear();

    return 0;
}

int Logger::openFile(const char* path, size_t id)
{
    int s = 0;
    
    // if there is an entry, it must be open
    LoggerMap::iterator it = logs.find(id);
    if ( it != logs.end() )
        return 0;
    
#ifdef POSIX
    FILE* file = NULL;
    if ( path != NULL )
    {
        file = stdout;
    }
    else
    {
        s = fopen_s(&file, path, "a");
        if ( s != 0 )
            return s;
    }
    setbuf(file, NULL);
#else
    HANDLE file = INVALID_HANDLE_VALUE;
    if ( path != NULL )
    {
        file = CreateFileA(
            path,
            FILE_APPEND_DATA,
            FILE_SHARE_READ,
            NULL,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
    }
    else
    {
        file = CreateFileA(
            "CONOUT$",
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_WRITE,
            NULL,
            FILE_SHARE_WRITE,
            NULL,
            NULL
        );
    }
    if ( file == INVALID_HANDLE_VALUE )
    {
        return GetLastError();
    }
#endif

    LOG_DATA ld = {NULL, file};
    logs.emplace(id, ld);

    return s;
}

int Logger::closeFile(size_t id)
{
    int s = 0;
    
    LoggerMap::iterator it = logs.find(id);
    if ( it == logs.end() )
        return -1;
    
#ifdef POSIX
    if ( it->second.file )
        fclose(it->second.file);
#else
    if ( it->second.file )
        CloseHandle(it->second.file);
#endif

    logs.erase(it);
    
    return s;
}
        
int Logger::logInfo(size_t id, uint32_t flags, const char *format, ...)
{
    int s = 0;
    //FILE* file = NULL;
    HANDLE file = NULL;
    char fts[FORMATED_TIME_STAMP_SIZE];
    int bWritten = 0;
    char sBuffer[LOG_BUFFER_SIZE];
    char* dBuffer = NULL;
    char* buffer = NULL;
    size_t bufferSize = 0;
    
    LoggerMap::iterator it = logs.find(id);
    if ( it == logs.end() )
        return -1;

    file = it->second.file;
    if ( file == NULL )
        return -2;
    
    va_list args;
    va_start(args, format);
    
    int vaLen = _vscprintf(format, args) + (int)strlen(LOGGER_PREFIX_DBG)+1 + FORMATED_TIME_STAMP_SIZE+4 + 1 + 1 ; // terminating '\0'
    if ( vaLen < LOG_BUFFER_SIZE )
    {
        buffer = sBuffer;
        bufferSize = LOG_BUFFER_SIZE;
    }
    else
    {
        dBuffer = (char*) malloc(vaLen * sizeof(char));
        if ( dBuffer == NULL )
        {
            s = GetLastError();
            StringUtil::getFormatedTime(fts, FORMATED_TIME_STAMP_SIZE);
            bWritten = sprintf_s(sBuffer, LOG_BUFFER_SIZE, "[%s]\nError (0x%x): Allocating log buffer failed!\n", fts, s);
            writeBuffer(file, sBuffer, bWritten);
            return s;
        }
        buffer = dBuffer;
        bufferSize = vaLen;
    }

    if ( flags & LOGGER_FLAG_TIME_STAMP )
    {
        StringUtil::getFormatedTime(fts, FORMATED_TIME_STAMP_SIZE);
        bWritten += sprintf_s(&buffer[bWritten], bufferSize-bWritten, "[%s]\n", fts);
    }

    if ( flags & LOGGER_FLAG_DBG )
    {
        bWritten += sprintf_s(&buffer[bWritten], bufferSize-bWritten, LOGGER_PREFIX_DBG " ");
    }

    bWritten += vsprintf_s(&buffer[bWritten], bufferSize-bWritten, format, args);
    va_end(args);

    if ( flags & LOGGER_FLAG_NEW_LINE )
    {
        bWritten += sprintf_s(&buffer[bWritten], bufferSize-bWritten, "\n");
    }

    s = writeBuffer(file, buffer, bWritten);

    if ( dBuffer != NULL )
        free(dBuffer);

    return s;
}

int Logger::logError(size_t id, uint32_t code, const char *format, ...)
{
    int s = 0;
    char fts[FORMATED_TIME_STAMP_SIZE];
    //FILE* file = NULL;
    HANDLE file = NULL;
    int bWritten = 0;
    char sBuffer[LOG_BUFFER_SIZE];
    char* dBuffer = NULL;
    char* buffer = NULL;
    size_t bufferSize = 0;
    
    LoggerMap::iterator it = logs.find(id);
    if ( it == logs.end() )
        return -1;

    file = it->second.file;
    if ( file == NULL )
        return -2;
    
    va_list args;
    va_start(args, format);
    
    int vaLen = _vscprintf(format, args) + 20 + FORMATED_TIME_STAMP_SIZE+4 + 1; // terminating '\0'
    if ( vaLen < LOG_BUFFER_SIZE )
    {
        buffer = sBuffer;
        bufferSize = LOG_BUFFER_SIZE;
    }
    else
    {
        dBuffer = (char*) malloc(vaLen * sizeof(char));
        if ( dBuffer == NULL )
        {
            s = GetLastError();
            StringUtil::getFormatedTime(fts, FORMATED_TIME_STAMP_SIZE);
            bWritten = sprintf_s(sBuffer, LOG_BUFFER_SIZE, " [%s]\nError (0x%x): Allocating log buffer failed!\n", fts, s);
            writeBuffer(file, sBuffer, bWritten);
            return s;
        }
        buffer = dBuffer;
        bufferSize = vaLen;
    }
    
    StringUtil::getFormatedTime(fts, FORMATED_TIME_STAMP_SIZE);
    bWritten += sprintf_s(&buffer[bWritten], bufferSize-bWritten, "[%s]\n", fts);

    bWritten += sprintf_s(&buffer[bWritten], bufferSize-bWritten, "Error (0x%x): ", code);
    
    bWritten += vsprintf_s(&buffer[bWritten], bufferSize-bWritten, format, args);
    va_end(args);

    s = writeBuffer(file, buffer, bWritten);

    if ( dBuffer != NULL )
        free(dBuffer);
    
    return s;
}

#ifdef POSIX
int Logger::writeBuffer(FILE* file, const char* buffer, uint32_t bufferSize)
{
    size_t w = fwrite(buffer, 1, bufferSize, file);
    if ( w != bufferSize )
        return GetLastError();
    return 0;
}
#else
int Logger::writeBuffer(HANDLE file, const char* buffer, uint32_t bufferSize)
{
    ULONG bWritten;
    BOOL b = WriteFile(
        file,
        buffer, 
        bufferSize,
        &bWritten,
        NULL
    );

    if ( !b )
        return GetLastError();
    return 0;
}
#endif

#ifndef _UTILS_LOGGER_H
#define _UTILS_LOGGER_H

#include <windows.h>

#include <stdlib.h>
#include <stdint.h>

#include <map>
#include <set>
#include <string>
#include <vector>

// Log info flags
#define LOGGER_FLAG_NEW_LINE    (0x1) // Add a new line 
#define LOGGER_FLAG_TIME_STAMP  (0x2) // Add a timestamp: string [<timestamp>]
#define LOGGER_FLAG_DBG         (0x4) // Add debug prefix [Dbg]

#define LOGGER_PREFIX_DBG "[Dbg]"


class Logger
{
    struct LOG_DATA {
        const char* path; // unused, should be NULL
#ifdef POSIX
        FILE* file;
#else
        HANDLE file;
#endif
    };
    protected:
        typedef std::map<const size_t, LOG_DATA> LoggerMap;
        LoggerMap logs;

    public:
        Logger() = default;
        ~Logger();

        /**
         * Open a log file and add it to the map with the provided index.
         * 
         * @param path const char* Path to the file. Pass NULL for stdout.
         * @param id size_t Arbitrary index/identifier of the file.
         * @return int success/error code
         */
        int openFile(const char* path, size_t id);
        
        /**
         * Close a log file with the given index and remove from the map.
         * 
         * @param id size_t Index/identifier of the file.
         * @return int success/error code
         */
        int closeFile(size_t id);
        
        /**
         * Close and clear all log files
         */
        int clear();
    
        /**
         * Add an entry to a log.
         * 
         * @param id size_t Index/identifier of the file.
         * @param flags uint32_t Modifiere flags. See "Log info flags"
         * @param format ... const char* the format string like it would be passed to printf
         * @return int success/error code
         */
        int logInfo(size_t id, uint32_t flags, const char *format, ...);
        
        /**
         * Add an error entry to a log.
         * Specially formated: "Error (<ErrorCode>): format ... [<timestamp>]"
         * 
         * @param id size_t Index/identifier of the file.
         * @param code uint32_t Error code
         * @param format ... const char* the format string like it would be passed to printf
         * @return int success/error code
         */
        int logError(size_t id, uint32_t code, const char *format, ...);


    private:
#ifdef POSIX
        int writeBuffer(FILE* file, const char* buffer, uint32_t bufferSize);
#else
        int writeBuffer(HANDLE file, const char* buffer, uint32_t bufferSize);
#endif
};


#endif

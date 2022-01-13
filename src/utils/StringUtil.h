#ifndef _UTILS_STRING_UTIL_H
#define _UTILS_STRING_UTIL_H


#include <windows.h>

#include <stdint.h>

#include <string>
#include <vector>



class StringUtil
{
    public:

        /**
         * Trim from start.
         *
         * @param	s const char* the string to trim
         */
        static
        const char* ltrim(const char* s);

        /**
         * Trim from end.
         *
         * @param	s const char* the string to trim
         */
        static
        const char* rtrim(char* s);

        /**
         * Trim from both ends.
         *
         * @param	s const char* the string to trim
         */
        static
        const char* trim(char* s);
        
        /**
         * Count lines in text buffer.
         *
         * @param	Buffer uint8_t* text bufffer with lines
         * @param	BufferSize size_t size of Buffer in bytes
         * @param	NrLines uint32_t* resulting counted number of lines
         * @return	int status/error code
         */
        static
        int CountLines(
            uint8_t* Buffer,
            size_t BufferSize,
            uint32_t* NrLines
        );	
        
        /**
         * Check if string starts with
         *
         * @param	pre char* searched prefix
         * @param	char* str string to search in
         * @return	bool
         */
        static
        bool startsWith(const char *pre, const char *str);

        /**
        * Split string into parts by delimiter.
        *
        * @param	s string& the string to split
        * @param	delim char the splitting delimiter
        * @param	elems vector<string> the splitted elements
        */
        static
        void split(const std::string& s, char delim, std::vector<std::string>* elems);

        /**
            * Split string into vector(parts) by delimiter.
            *
            * @param	s string& the string to split
            * @param	delim char the splitting delimiter
            */
        static
        std::vector<std::string> split(const std::string &s, char delim);
        
        /**
            * Parse string to boolean.
            * Returns true, if values is "true" or > 0.
            *
            * @param	value string
            * @return	bool
            */
        static
        bool toBool(std::string value);

        /**
         * Write formated local time into buffer:
         * "dd.mm.yyyy hh:mm:ss"
         */
        static
        bool getFormatedTime(char* buffer, size_t n, bool lineBreak=false, const char* prefix="", const char* postfix="");

};

#endif

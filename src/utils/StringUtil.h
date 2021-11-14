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

        static
        int CountLines(
            uint8_t* Buffer,
            size_t BufferSize,
            uint32_t* NrLines
        );	
        
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

};

#endif

#ifndef _UTILS_CONFIG_FILE_PARSER_H
#define _UTILS_CONFIG_FILE_PARSER_H

#include <map>
#include <set>
#include <string>
#include <vector>


#include "ConfigFileParser.h"



class SChatConfigFileParser : public ConfigFileParser
{
    protected:

    public:
        SChatConfigFileParser();
        explicit SChatConfigFileParser(const char marker);
        SChatConfigFileParser(const std::vector<std::string>& keys, const char marker);

        bool update(const string& src);
};


#endif

#include "ConfigFileParser.h"

#include <fstream>
#include <iostream>

#include "../files/Files.h"
#include "StringUtil.h"

using namespace std;

SChatConfigFileParser::SChatConfigFileParser()
    : ConfigFileParser()
{
}

SChatConfigFileParser::SChatConfigFileParser(const char marker)
    : ConfigFileParser(marker)
{
}

SChatConfigFileParser::SChatConfigFileParser(const vector<string>& keys, const char marker)
    : ConfigFileParser(keys, marker)
{
}

bool SChatConfigFileParser::update(const string& src)
{
    if ( !fileExists(&src[0]) )
        return false;

    ifstream ifs(src);
    string line;
    string line_key;
    uint16_t key_start;

    while ( getline(ifs, line) )
    {
        if ( line.empty() )
            continue;

        if ( line[0] == marker )
        {
            key_start = 1;
            while ( key_start < line.size() && line[key_start] == ' ' )
                key_start++;
            if ( key_start >= line.size() ) 
                continue;

            line_key = line.substr(key_start);

            for ( const string& k : keys )
            {
                if ( line_key == k )
                {
                    getline(ifs, line);
                    values.emplace(k, line);
                    break;
                }
            }
        }
    }

    return true;
}

#ifdef _WIN32
#pragma warning( disable : 4996 )
#endif

#include "ConfigFileParser.h"

#include <fstream>
#include <iostream>

#include "../files/Files.h"
#include "StringUtil.h"

using namespace std;

ConfigFileParser::ConfigFileParser()
    : marker('#')
{
}

ConfigFileParser::ConfigFileParser(const char marker)
    : marker(marker)
{
}

ConfigFileParser::ConfigFileParser(const vector<string>& keys, const char marker)
    : marker(marker),
        keys(keys)
{
}

bool ConfigFileParser::run(const string& src)
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

string ConfigFileParser::getRawValue(const string& key)
{
    ValuesMap::iterator it = values.find(key);
    if ( it == values.end() )
        return "";

    return it->second;
}

string ConfigFileParser::getStringValue(const string& key, size_t max, const string& def)
{
    std::string raw = getRawValue(key);
    if ( raw.empty() )
        return def;

    if ( max > 0 )
        return string(StringUtil::trim(&raw[0])).substr(0,max);
    else
        return StringUtil::trim(&raw[0]);
}

int ConfigFileParser::setStringValue(const string& key, const string& value, size_t size)
{
    ValuesMap::iterator it = values.find(key);
    if ( it == values.end() )
        return 1;

    it->second = value;
    (size);

    return 0;
}

vector<string> ConfigFileParser::getStringListValue(const string& key, const vector<string>& def)
{
    std::string raw = getRawValue(key);
    if ( raw.empty() )
        return def;

    vector<string> r;
    vector<string> parts = StringUtil::split(&raw[0], ',');
    for ( string& p : parts )
        r.emplace_back(StringUtil::trim(&p[0]));

    return r;
}

set<string> ConfigFileParser::getStringSetValue(const string& key, const set<string>& def)
{
    std::string raw = getRawValue(key);
    if ( raw.empty() )
        return def;

    set<string> r;
    vector<string> parts = StringUtil::split(raw, ',');
    for ( string& p : parts )
        r.emplace(StringUtil::trim(&p[0]));

    return r;
}

bool ConfigFileParser::getBoolValue(const string& key, bool def)
{
    std::string raw = getRawValue(key);
    if ( raw.empty() )
        return def;

    return StringUtil::toBool(&raw[0]);
}

uint16_t ConfigFileParser::getUInt16Value(const string& key, uint16_t def)
{
    std::string raw = getRawValue(key);
    if ( raw.empty() )
        return def;

    return (uint16_t) stoul(raw, nullptr, 0);
}

int ConfigFileParser::setUInt16Value(const string& key, uint16_t value)
{
    ValuesMap::iterator it = values.find(key);
    if ( it == values.end() )
        return 1;

    it->second = to_string(value);

    return 0;
}

map<string, string>* ConfigFileParser::getValues()
{
    return &values;
}

int ConfigFileParser::save(const string& path)
{
    FILE* file = NULL;
    char buffer[0x100];

    if ( values.empty() )
        return 0;

    file = fopen(&path[0], "w");
    if ( file == NULL )
        return -1;

    ValuesMap::const_iterator it = values.begin();
    sprintf(buffer, "# %s\n", it->first.c_str());
    fwrite(buffer, 1, it->first.size()+3, file);
    fwrite(&it->second[0], 1, it->second.size(), file);

    for ( ++it; it != values.end(); ++it )
    {
        sprintf(buffer, "\n# %s\n", it->first.c_str());
        fwrite(buffer, 1, it->first.size()+4, file);
        fwrite(&it->second[0], 1, it->second.size(), file);
    }

    if ( file != NULL )
        fclose(file);

    return 0;
}

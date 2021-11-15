#ifndef _UTILS_CONFIG_FILE_PARSER_H
#define _UTILS_CONFIG_FILE_PARSER_H

#include <map>
#include <set>
#include <string>
#include <vector>



class ConfigFileParser
{
    protected:
        using ValuesMap = std::map<std::string, std::string>;
        const char marker;
        ValuesMap values;
        std::vector<std::string> keys;

    public:
        ConfigFileParser();
        explicit ConfigFileParser(const char marker);
        ConfigFileParser(const std::vector<std::string>& keys, const char marker);

        bool run(const std::string& src);
        std::string getRawValue(const std::string& key);
        
        std::string getStringValue(const std::string& key, size_t max, const std::string& def);
        int setStringValue(const std::string& key, const std::string& value, size_t size);

        std::vector<std::string> getStringListValue(const std::string& key, const std::vector<std::string>& def);
        std::set<std::string> getStringSetValue(const std::string& key, const std::set<std::string>& def);

        uint16_t getUInt16Value(const std::string& key, uint16_t def);
        int setUInt16Value(const std::string& key, uint16_t value);

        bool getBoolValue(const std::string& key, bool def);
        ValuesMap* getValues();
        
        int save(const std::string& path);
};


#endif

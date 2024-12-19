#ifndef XML_TAG_MAPPER_H
#define XML_TAG_MAPPER_H

#include <map>
#include <string>
#include <pugixml.hpp>

class XMLTagMapper {
    std::map<std::string, std::string> tag_mapping;
    void initializeMapping();

public:
    XMLTagMapper();

    [[nodiscard]] std::string deobfuscateTag(const std::string& tag) const;
    [[nodiscard]] std::string obfuscateTag(const std::string& tag) const;
    void transformNode(pugi::xml_node& node, bool deobfuscate);
    std::string transformXML(const std::string& xml, bool deobfuscate = true);
    void printMapping() const;
    void addMapping(const std::string& obfuscated, const std::string& clear);
};

#endif // XML_TAG_MAPPER_H
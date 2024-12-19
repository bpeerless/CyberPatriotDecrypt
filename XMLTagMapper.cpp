#include "XMLTagMapper.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>

void XMLTagMapper::initializeMapping() {
    // Root element
    tag_mapping["e665"] = "CyberPatriotResource";
    
    // Basic metadata
    tag_mapping["bd07"] = "ResourceID";
    tag_mapping["d539"] = "Tier";
    tag_mapping["b799"] = "Branding";
    tag_mapping["da76"] = "Title";
    tag_mapping["bda1"] = "TeamKey";
    
    // URLs and endpoints
    tag_mapping["db90"] = "ScoringUrl";
    tag_mapping["e7ca"] = "ScoreboardUrl";
    tag_mapping["bb34"] = "ReadmeUrl";
    tag_mapping["ce43"] = "SupportUrl";
    tag_mapping["b20e"] = "HideScoreboard";
    
    // Server configuration
    tag_mapping["e708"] = "TimeServers";
    tag_mapping["a042"] = "Primary";
    tag_mapping["b71e"] = "Secondary";
    
    // Time configuration
    tag_mapping["f809"] = "DestructImage";
    tag_mapping["d88d"] = "Before";
    tag_mapping["c634"] = "After";
    tag_mapping["bef5"] = "Uptime";
    tag_mapping["a9b1"] = "Playtime";
    tag_mapping["edd9"] = "InvalidClient";
    tag_mapping["fa86"] = "InvalidTeam";
    
    // Competition phases
    tag_mapping["f1b5"] = "DisableFeedback";
    tag_mapping["cc52"] = "NoConnection";
    tag_mapping["ab71"] = "Unknown";
    
    // Boolean flags
    tag_mapping["b20e"] = "IsActive";

    // Additional discovered tags
    tag_mapping["ee2b"] = "Rule";
    tag_mapping["a71b"] = "RuleGroup";
    tag_mapping["ed93"] = "ScoreWeight";
    tag_mapping["ff90"] = "MaxPoints";
    tag_mapping["a6a0"] = "MinPoints";
}

XMLTagMapper::XMLTagMapper() {
    initializeMapping();
}

std::string XMLTagMapper::deobfuscateTag(const std::string& tag) const {
    auto it = tag_mapping.find(tag);
    return (it != tag_mapping.end()) ? it->second : tag;
}

std::string XMLTagMapper::obfuscateTag(const std::string& tag) const {
    for (const auto& pair : tag_mapping) {
        if (pair.second == tag) {
            return pair.first;
        }
    }
    return tag;
}

void XMLTagMapper::transformNode(pugi::xml_node& node, bool deobfuscate) {
    // First, transform the current node's name
    std::string new_name = deobfuscate ?
        deobfuscateTag(node.name()) :
        obfuscateTag(node.name());
    node.set_name(new_name.c_str());

    // Then recursively transform all child nodes
    for (pugi::xml_node child = node.first_child(); child; child = child.next_sibling()) {
        transformNode(child, deobfuscate);
    }
}

std::string XMLTagMapper::transformXML(const std::string& xml, bool deobfuscate) {
    pugi::xml_document doc;
    pugi::xml_parse_result result = doc.load_string(xml.c_str());

    if (!result) {
        std::cerr << "XML Parse Error: " << result.description() << std::endl;
        return xml;
    }

    // Transform starting from the root node
    pugi::xml_node root = doc.first_child();
    if (root) {
        transformNode(root, deobfuscate);
    }

    // Output the transformed XML
    std::ostringstream oss;
    doc.save(oss, "  ", pugi::format_indent | pugi::format_no_empty_element_tags);
    return oss.str();
}

void XMLTagMapper::printMapping() const {
    std::cout << "XML Tag Mapping:\n";
    std::cout << std::string(50, '-') << std::endl;
    for (const auto& pair : tag_mapping) {
        std::cout << std::left << std::setw(10) << pair.first 
                 << " -> " << pair.second << std::endl;
    }
}

void XMLTagMapper::addMapping(const std::string& obfuscated, const std::string& clear) {
    tag_mapping[obfuscated] = clear;
}
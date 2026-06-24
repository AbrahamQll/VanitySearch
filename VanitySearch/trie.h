// trie.h

#pragma once

#include <string>
#include <unordered_map>
#include <memory>

class TrieNode {
public:
    std::unordered_map<char, std::shared_ptr<TrieNode>> children;
    bool is_end_of_word;

    TrieNode() : is_end_of_word(false) {}
};

class Trie {
public:
    Trie() {
        root = std::make_shared<TrieNode>();
    }

    void insert(const std::string& word) {
        auto current = root;
        for (char ch : word) {
            if (current->children.find(ch) == current->children.end()) {
                current->children[ch] = std::make_shared<TrieNode>();
            }
            current = current->children[ch];
        }
        current->is_end_of_word = true;
    }

    // Checks if the given address string starts with any of the patterns in the Trie.
    bool search_prefix(const std::string& address) const {
        auto current = root;
        for (char ch : address) {
            if (current->is_end_of_word) {
                // We've matched a full pattern prefix
                return true;
            }
            if (current->children.find(ch) == current->children.end()) {
                // No matching path, so no prefix match is possible
                return false;
            }
            current = current->children[ch];
        }
        // The address itself might be a pattern
        return current->is_end_of_word;
    }

private:
    std::shared_ptr<TrieNode> root;
};
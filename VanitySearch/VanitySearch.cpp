// VanitySearch.cpp

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include <stdexcept> // For std::stoi exception handling

#include "crypto.h"
#include "trie.h"
#include "rng_buffer.h"
#include <secp256k1.h>

#pragma warning(disable : 4996) 

// --- Global Variables (Unchanged) ---
Trie p2pkh_trie;
Trie p2sh_trie;
size_t p2pkh_pattern_count = 0;
size_t p2sh_pattern_count = 0;
std::atomic<unsigned long long> keys_generated(0);
std::atomic<bool> solution_found(false);
std::mutex cout_mutex;
std::mutex file_mutex;

// --- Helper Functions (Unchanged) ---
void save_result(const std::string& address_type, const std::string& address, const std::string& wif_key) {
    std::lock_guard<std::mutex> lock(file_mutex);
    std::ofstream outfile("found.txt", std::ios_base::app);
    outfile << "Type:    " << address_type << std::endl;
    outfile << "Address: " << address << std::endl;
    outfile << "WIF:     " << wif_key << std::endl;
    outfile << "------------------------------------------" << std::endl;
}

// --- Worker Function (Unchanged) ---
void search_worker() {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx) {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cerr << "CRITICAL: Thread context creation failed. Thread cannot start.\n";
        return;
    }
    Seeded_RNG rng;
    PrivateKeyBytes private_key;
    PublicKeyBytes compressed_pubkey;
    PublicKeyBytes uncompressed_pubkey;
    while (!solution_found) {
        if (!rng.get_private_key(private_key)) continue;
        if (!create_public_keys(ctx, private_key, compressed_pubkey, uncompressed_pubkey)) continue;
        keys_generated++;
        if (p2pkh_pattern_count > 0) {
            std::string p2pkh_uncompressed_addr = create_p2pkh_address(uncompressed_pubkey);
            if (p2pkh_trie.search_prefix(p2pkh_uncompressed_addr)) {
                std::string wif = private_key_to_wif_uncompressed(private_key);
                {
                    std::lock_guard<std::mutex> lock(cout_mutex);
                    std::cout << "\n---!!! P2PKH (Uncompressed) MATCH FOUND !!!---\n";
                    std::cout << "Address: " << p2pkh_uncompressed_addr << "\n";
                    std::cout << "WIF Key: " << wif << "\n";
                    std::cout << "-------------------------------------------\n" << std::flush;
                }
                save_result("P2PKH (Uncompressed)", p2pkh_uncompressed_addr, wif);
            }
            std::string p2pkh_compressed_addr = create_p2pkh_address(compressed_pubkey);
            if (p2pkh_trie.search_prefix(p2pkh_compressed_addr)) {
                std::string wif = private_key_to_wif_compressed(private_key);
                {
                    std::lock_guard<std::mutex> lock(cout_mutex);
                    std::cout << "\n---!!! P2PKH (Compressed) MATCH FOUND !!!---\n";
                    std::cout << "Address: " << p2pkh_compressed_addr << "\n";
                    std::cout << "WIF Key: " << wif << "\n";
                    std::cout << "-----------------------------------------\n" << std::flush;
                }
                save_result("P2PKH (Compressed)", p2pkh_compressed_addr, wif);
            }
        }
        if (p2sh_pattern_count > 0) {
            std::string p2sh_address = create_p2sh_address(compressed_pubkey);
            if (p2sh_trie.search_prefix(p2sh_address)) {
                std::string wif = private_key_to_wif_compressed(private_key);
                {
                    std::lock_guard<std::mutex> lock(cout_mutex);
                    std::cout << "\n---!!! P2SH (SegWit) MATCH FOUND !!!---\n";
                    std::cout << "Address: " << p2sh_address << "\n";
                    std::cout << "WIF Key: " << wif << "\n";
                    std::cout << "-------------------------------------\n" << std::flush;
                }
                save_result("P2SH-P2WPKH", p2sh_address, wif);
            }
        }
    }
    secp256k1_context_destroy(ctx);
}


// --- Main Function ---
int main(int argc, char* argv[]) {
    // --- UPDATED: Argument Parsing ---
    if (argc < 2 || argc > 3) {
        std::cerr << "Usage: " << argv[0] << " <patterns_file.txt> [thread_count]\n";
        std::cerr << "  [thread_count] is optional. If not provided, it will use all available CPU cores.\n";
        return 1;
    }

    std::cout << "--- VanitySearch v1.6 (Thread Control) ---\n";

    // --- SELF-TEST (Unchanged) ---
    // ... (self-test code is exactly the same as before) ...
    std::cout << "--- RUNNING COMPREHENSIVE SELF-TEST ---\n";
    secp256k1_context* test_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    PrivateKeyBytes test_key;
    const char* test_hex = "18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725";
    test_key.resize(32);
    for (int i = 0; i < 32; ++i) {
        test_key[i] = (stoul(std::string(test_hex + 2 * i, 2), nullptr, 16));
    }
    PublicKeyBytes test_pub_comp, test_pub_uncomp;
    if (!create_public_keys(test_ctx, test_key, test_pub_comp, test_pub_uncomp)) {
        std::cerr << "Failed to create test public keys.\n";
        secp256k1_context_destroy(test_ctx);
        return -1;
    }
    std::string addr_comp = create_p2pkh_address(test_pub_comp);
    std::string wif_comp = private_key_to_wif_compressed(test_key);
    std::string addr_uncomp = create_p2pkh_address(test_pub_uncomp);
    std::string wif_uncomp = private_key_to_wif_uncompressed(test_key);
    const std::string expected_addr_comp = "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs";
    const std::string expected_wif_comp = "Kx45GeUBSMPReYQwgXiKhG9FzNXrnCeutJp4yjTd5kKxCitadm3C";
    const std::string expected_addr_uncomp = "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM";
    const std::string expected_wif_uncomp = "5J1F7GHadZG3sCCKHCwg8Jvys9xUbFsjLnGec4H125Ny1V9nR6V";
    bool pass = (addr_comp == expected_addr_comp && wif_comp == expected_wif_comp && addr_uncomp == expected_addr_uncomp && wif_uncomp == expected_wif_uncomp);
    secp256k1_context_destroy(test_ctx);
    if (pass) {
        std::cout << "--- SELF-TEST PASSED (Compressed & Uncompressed) ---\n\n";
    }
    else {
        std::cerr << "\n--- !!! SELF-TEST FAILED !!! ---\n";
        return -1;
    }

    // --- Loading Patterns (Unchanged) ---
    std::cout << "Loading patterns from file... (this may take a moment for large files)\n";
    std::ifstream patterns_file(argv[1]);
    if (!patterns_file) { std::cerr << "Error: Could not open patterns file: " << argv[1] << "\n"; return 1; }
    std::string line;
    while (std::getline(patterns_file, line)) {
        if (!line.empty() && line.length() > 1) {
            if (line[0] == '1') { p2pkh_trie.insert(line); p2pkh_pattern_count++; }
            else if (line[0] == '3') { p2sh_trie.insert(line); p2sh_pattern_count++; }
        }
    }
    std::cout << "Loaded " << p2pkh_pattern_count << " P2PKH ('1') patterns into Trie.\n";
    std::cout << "Loaded " << p2sh_pattern_count << " P2SH ('3') patterns into Trie.\n";
    if (p2pkh_pattern_count == 0 && p2sh_pattern_count == 0) { std::cerr << "Error: No valid patterns found.\n"; return 1; }

    // --- UPDATED: Determine Thread Count ---
    unsigned int num_threads = std::thread::hardware_concurrency(); // Default to max
    if (argc == 3) {
        try {
            int user_threads = std::stoi(argv[2]);
            if (user_threads > 0 && user_threads <= 256) { // Set a reasonable upper limit
                num_threads = user_threads;
            }
            else {
                std::cerr << "Warning: Invalid thread count '" << argv[2] << "'. Using default.\n";
            }
        }
        catch (const std::invalid_argument& e) {
            std::cerr << "Warning: Invalid thread count '" << argv[2] << "'. Using default.\n";
        }
        catch (const std::out_of_range& e) {
            std::cerr << "Warning: Thread count '" << argv[2] << "' out of range. Using default.\n";
        }
    }
    if (num_threads == 0) num_threads = 1;

    std::cout << "Starting search on " << num_threads << " threads... (Press Ctrl+C to stop)\n\n";

    // --- Launching Threads & Reporting (Unchanged) ---
    std::vector<std::thread> threads;
    for (unsigned int i = 0; i < num_threads; ++i) threads.emplace_back(search_worker);
    unsigned long long last_keys = 0;
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        unsigned long long current_keys = keys_generated.load();
        double kps = (current_keys - last_keys) / 2.0;
        last_keys = current_keys;
        std::cout << "\rSpeed: " << static_cast<long long>(kps) << " k/s | Total checked: " << current_keys << "          " << std::flush;
    }
    for (auto& t : threads) { if (t.joinable()) t.join(); }
    return 0;
}
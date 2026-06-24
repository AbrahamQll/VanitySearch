#include "cuda_runtime.h"
#include "device_launch_parameters.h"
#include "CudaBTCGen.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <chrono>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <thread>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <iomanip>     // For standard formatting manipulators
#include <intrin.h>    // For __cpuid intrinsic
#include <immintrin.h> // Intel RDRAND Intrinsics

// Windows Cryptography API
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

// Target search structures
struct SearchTarget {
	uint8_t hash[20];
};

struct FoundHit {
	uint256 private_key;
	uint8_t hash160[20];
	uint8_t type; // 0 = P2PKH_C, 1 = P2PKH_U, 2 = P2SH
};

// Base58 Alphabet constant
const char* BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Thread Safety and Pre-generation Structures
std::queue<uint256> key_queue;
std::mutex queue_mutex;
std::condition_variable queue_cv;
bool stop_pregen_thread = false;
std::mutex results_mutex; // Mutex to serialize console printing and file writing

// ==========================================
// HOST HELPER FUNCTIONS
// ==========================================

void print_hex_256(const uint256& val) {
	for (int i = 7; i >= 0; i--) {
		printf("%08X", val.v[i]);
	}
}

// Host companion function to add uint256 on CPU
void host_add_uint256_uint64(uint256* a, uint64_t b) {
	uint64_t carry = b;
	for (int i = 0; i < 8; ++i) {
		uint64_t sum = (uint64_t)a->v[i] + carry;
		a->v[i] = (uint32_t)sum;
		carry = sum >> 32;
	}
}

void host_sub_uint256_uint64(uint256* a, uint64_t b) {
	uint64_t borrow = b;
	for (int i = 0; i < 8; ++i) {
		uint64_t diff = (uint64_t)a->v[i] - borrow;
		a->v[i] = (uint32_t)diff;
		borrow = (diff >> 63) & 1; // Propagate borrow bit
	}
}

// Helper to extract directory path from a file path
std::string get_directory_path(const std::string& filepath) {
	size_t found = filepath.find_last_of("/\\");
	if (found != std::string::npos) {
		return filepath.substr(0, found + 1);
	}
	return ""; // Current directory
}

// Check if hardware CPU execution supports RDRAND
bool cpu_supports_rdrand() {
	int cpuInfo[4] = { 0 };
	__cpuid(cpuInfo, 1);
	return (cpuInfo[2] & (1 << 30)) != 0; // Bit 30 of ECX
}

// ==========================================
// TAMPER-PROOF ENTROPY GENERATOR
// ==========================================

bool generate_tamper_free_key(uint256* out_key) {
	uint8_t entropy_pool[128] = { 0 };

	// Source 1: OS Cryptographic API
	uint8_t os_entropy[32] = { 0 };
	BCryptGenRandom(NULL, os_entropy, 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	memcpy(entropy_pool, os_entropy, 32);

	// Source 2: Direct Intel Hardware RDRAND (with runtime safeguard check)
	uint32_t hw_entropy[8] = { 0 };
	bool rdrand_ok = false;
	if (cpu_supports_rdrand()) {
		rdrand_ok = true;
		for (int i = 0; i < 8; ++i) {
			unsigned int val = 0;
			int retries = 10;
			while (retries > 0) {
				if (_rdrand32_step(&val)) {
					hw_entropy[i] = val;
					break;
				}
				retries--;
			}
			if (retries == 0) {
				rdrand_ok = false;
				break;
			}
		}
	}

	if (rdrand_ok) {
		memcpy(entropy_pool + 32, hw_entropy, 32);
	}
	else {
		// Clock fallback if hardware entropy instructions are restricted
		for (int i = 0; i < 8; ++i) {
			auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
			hw_entropy[i] = (uint32_t)(now ^ (now >> 32));
		}
		memcpy(entropy_pool + 32, hw_entropy, 32);
	}

	// Source 3: System State & High-Res Clock Jitter
	DWORD pid = GetCurrentProcessId();
	DWORD tid = GetCurrentThreadId();
	auto now_ticks = std::chrono::high_resolution_clock::now().time_since_epoch().count();
	uintptr_t stack_addr = (uintptr_t)&os_entropy;

	memcpy(entropy_pool + 64, &pid, sizeof(DWORD));
	memcpy(entropy_pool + 68, &tid, sizeof(DWORD));
	memcpy(entropy_pool + 72, &now_ticks, sizeof(now_ticks));
	memcpy(entropy_pool + 80, &stack_addr, sizeof(stack_addr));

	// SHA-256 Hashing of the mixed pool
	BCRYPT_ALG_HANDLE hAlg = NULL;
	BCRYPT_HASH_HANDLE hHash = NULL;
	DWORD cbHashObject = 0, cbHash = 0, cbData = 0;
	PBYTE pbHashObject = NULL;

	if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0) return false;
	if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0) != 0) goto Cleanup;

	pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
	if (NULL == pbHashObject) goto Cleanup;

	if (BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0) != 0) goto Cleanup;
	if (BCryptHashData(hHash, entropy_pool, sizeof(entropy_pool), 0) != 0) goto Cleanup;
	if (BCryptFinishHash(hHash, (PUCHAR)out_key->v, 32, 0) != 0) goto Cleanup;

	out_key->v[7] &= 0x7FFFFFFF; // Falls within secp256k1 scalar range

Cleanup:
	if (hHash) BCryptDestroyHash(hHash);
	if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
	if (pbHashObject) HeapFree(GetProcessHeap(), 0, pbHashObject);
	return true;
}

// Background Pregen Worker
void pregen_worker() {
	while (!stop_pregen_thread) {
		bool need_key = false;
		{
			std::lock_guard<std::mutex> lock(queue_mutex);
			if (key_queue.size() < 11) {
				need_key = true;
			}
		}

		if (need_key) {
			uint256 raw_key;
			if (generate_tamper_free_key(&raw_key)) {
				std::lock_guard<std::mutex> lock(queue_mutex);
				key_queue.push(raw_key);
				queue_cv.notify_one();
			}
		}
		else {
			// Sleep safely outside of key_queue mutex block to prevent host lock starvation
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
		}
	}
}

uint256 get_rotated_key() {
	std::unique_lock<std::mutex> lock(queue_mutex);
	while (key_queue.empty()) {
		queue_cv.wait(lock);
	}
	uint256 key = key_queue.front();
	key_queue.pop();
	return key;
}

// ==========================================
// BASE58 & BECH32 ENCODER DEVICES
// ==========================================

bool host_double_sha256(const uint8_t* data, size_t len, uint8_t* out_checksum) {
	BCRYPT_ALG_HANDLE hAlg = NULL;
	BCRYPT_HASH_HANDLE hHash = NULL;
	DWORD cbHashObject = 0, cbHash = 0, cbData = 0;
	PBYTE pbHashObject = NULL;
	uint8_t hash1[32];
	uint8_t hash2[32];

	if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0) return false;
	if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0) != 0) goto Cleanup;
	if (BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0) != 0) goto Cleanup;

	pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
	if (NULL == pbHashObject) goto Cleanup;

	if (BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0) != 0) goto Cleanup;
	if (BCryptHashData(hHash, (PBYTE)data, (ULONG)len, 0) != 0) goto Cleanup;
	if (BCryptFinishHash(hHash, hash1, 32, 0) != 0) goto Cleanup;
	BCryptDestroyHash(hHash);
	hHash = NULL;

	if (BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0) != 0) goto Cleanup;
	if (BCryptHashData(hHash, hash1, 32, 0) != 0) goto Cleanup;
	if (BCryptFinishHash(hHash, hash2, 32, 0) != 0) goto Cleanup;

	memcpy(out_checksum, hash2, 4);

Cleanup:
	if (hHash) BCryptDestroyHash(hHash);
	if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
	if (pbHashObject) HeapFree(GetProcessHeap(), 0, pbHashObject);
	return true;
}

std::string base58_encode(const uint8_t* data, size_t len) {
	std::vector<uint8_t> digits(len * 138 / 100 + 1, 0);
	size_t digits_len = 1;

	for (size_t i = 0; i < len; ++i) {
		uint32_t carry = data[i];
		for (size_t j = 0; j < digits_len; ++j) {
			carry += (uint32_t)digits[j] << 8;
			digits[j] = carry % 58;
			carry /= 58;
		}
		while (carry > 0) {
			digits_len++;
			if (digits_len > digits.size()) digits.resize(digits_len * 2, 0);
			digits[digits_len - 1] = carry % 58;
			carry /= 58;
		}
	}

	std::string result = "";
	size_t leading_zeros = 0;
	while (leading_zeros < len && data[leading_zeros] == 0) {
		leading_zeros++;
	}

	for (size_t i = 0; i < leading_zeros; ++i) {
		result += '1';
	}

	for (size_t i = digits_len; i > 0; --i) {
		result += BASE58_ALPHABET[digits[i - 1]];
	}

	return result;
}

std::string base58check_encode(uint8_t version, const uint8_t* hash160) {
	uint8_t buffer[25];
	buffer[0] = version;
	memcpy(buffer + 1, hash160, 20);

	uint8_t checksum[4];
	host_double_sha256(buffer, 21, checksum);
	memcpy(buffer + 21, checksum, 4);

	return base58_encode(buffer, 25);
}

uint32_t bech32_polymod(const std::vector<uint8_t>& values) {
	uint32_t chk = 1;
	static const uint32_t generator[] = { 0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3 };
	for (size_t i = 0; i < values.size(); ++i) {
		uint8_t top = chk >> 25;
		chk = ((chk & 0x1ffffff) << 5) ^ values[i];
		for (int j = 0; j < 5; ++j) {
			chk ^= (((top >> j) & 1) ? generator[j] : 0);
		}
	}
	return chk;
}

bool convert_bits(const std::vector<uint8_t>& in, int from, int to, bool pad, std::vector<uint8_t>& out) {
	int acc = 0;
	int bits = 0;
	int maxv = (1 << to) - 1;
	int max_acc = (1 << (from + to - 1)) - 1;
	for (size_t i = 0; i < in.size(); ++i) {
		acc = ((acc << from) | in[i]) & max_acc;
		bits += from;
		while (bits >= to) {
			bits -= to;
			out.push_back((acc >> bits) & maxv);
		}
	}
	if (pad) {
		if (bits) {
			out.push_back((acc << (to - bits)) & maxv);
		}
	}
	else if (bits >= from || ((acc << (to - bits)) & maxv)) {
		return false;
	}
	return true;
}

std::string bech32_encode(const uint8_t* hash160) {
	std::vector<uint8_t> in_bytes(hash160, hash160 + 20);
	std::vector<uint8_t> converted;
	if (!convert_bits(in_bytes, 8, 5, true, converted)) return "";

	std::vector<uint8_t> values;
	values.push_back(0); // Witness version 0 (bc1q)
	values.insert(values.end(), converted.begin(), converted.end());

	std::vector<uint8_t> check_input = { 3, 3, 0, 2, 3 }; // hrp_expand("bc")
	check_input.insert(check_input.end(), values.begin(), values.end());
	check_input.insert(check_input.end(), 6, 0);

	uint32_t chk = bech32_polymod(check_input) ^ 1;

	std::string addr = "bc1q";
	const char* charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
	for (size_t i = 0; i < converted.size(); ++i) {
		addr += charset[converted[i]];
	}
	for (int i = 0; i < 6; ++i) {
		addr += charset[(chk >> (5 * (5 - i))) & 31];
	}
	return addr;
}

// ==========================================
// HOST DECODING & ADDRESS PARSING FUNCTIONS
// ==========================================

uint256 hex_to_uint256(const std::string& hex) {
	uint256 val = { 0 };
	for (int i = 0; i < 8; ++i) {
		std::string part = hex.substr((7 - i) * 8, 8);
		val.v[i] = std::stoul(part, nullptr, 16);
	}
	return val;
}

bool base58_decode(const std::string& str, std::vector<uint8_t>& out) {
	std::vector<uint8_t> bytes;
	for (char c : str) {
		const char* p = strchr(BASE58_ALPHABET, c);
		if (!p) return false;
		int carry = p - BASE58_ALPHABET;
		for (size_t i = 0; i < bytes.size(); ++i) {
			carry += (int)bytes[i] * 58;
			bytes[i] = carry & 0xFF;
			carry >>= 8;
		}
		while (carry > 0) {
			bytes.push_back(carry & 0xFF);
			carry >>= 8;
		}
	}
	for (char c : str) {
		if (c == '1') bytes.push_back(0);
		else break;
	}
	out.clear();
	out.reserve(bytes.size());
	for (auto it = bytes.rbegin(); it != bytes.rend(); ++it) {
		out.push_back(*it);
	}
	return true;
}

bool parse_address_to_hash160(const std::string& addr, uint8_t* out_hash, uint8_t* out_type) {
	// 1. BECH32 (bc1q...)
	// Start parsing conversion bits at index 4 (the first character of the witness program)
	if (addr.size() == 42 && addr.substr(0, 4) == "bc1q") {
		const char* charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
		std::vector<uint8_t> values;
		for (size_t i = 4; i < addr.size() - 6; ++i) {
			const char* p = strchr(charset, addr[i]);
			if (!p) return false;
			values.push_back(p - charset);
		}
		std::vector<uint8_t> decoded;
		if (!convert_bits(values, 5, 8, false, decoded)) return false;
		if (decoded.size() == 20) {
			memcpy(out_hash, decoded.data(), 20);
			*out_type = 3;
			return true;
		}
	}

	// 2. Base58 (P2PKH/P2SH) with checksum validation
	std::vector<uint8_t> decoded;
	if (base58_decode(addr, decoded) && decoded.size() == 25) {
		uint8_t checksum[4];
		if (!host_double_sha256(decoded.data(), 21, checksum)) return false;
		if (memcmp(checksum, decoded.data() + 21, 4) != 0) return false;

		memcpy(out_hash, decoded.data() + 1, 20);
		if (decoded[0] == 0x00) {
			*out_type = 0;
		}
		else if (decoded[0] == 0x05) {
			*out_type = 2;
		}
		else {
			return false;
		}
		return true;
	}
	return false;
}

bool compare_targets(const SearchTarget& a, const SearchTarget& b) {
	for (int i = 0; i < 20; ++i) {
		if (a.hash[i] != b.hash[i]) return a.hash[i] < b.hash[i];
	}
	return false;
}

// ==========================================
// TEST ACCURACY RUNNER KERNEL
// ==========================================

__global__ void run_test_kernel(uint256 private_key, GPUResult* d_out) {
	ec_point_affine pub_key;
	scalar_multiply(&private_key, &pub_key);
	hash160_compressed(&pub_key, d_out->compressed);
	hash160_uncompressed(&pub_key, d_out->uncompressed);
	hash160_segwit(d_out->compressed, d_out->segwit);
}

// ==========================================
// CUDA MULTI-TARGET SEARCH KERNEL
// ==========================================

__device__ __forceinline__ bool binary_search_targets(const uint8_t* hash, const SearchTarget* targets, int count) {
	int low = 0;
	int high = count - 1;
	while (low <= high) {
		int mid = low + (high - low) / 2;
		int cmp = 0;
		for (int i = 0; i < 20; ++i) {
			if (hash[i] < targets[mid].hash[i]) { cmp = -1; break; }
			if (hash[i] > targets[mid].hash[i]) { cmp = 1; break; }
		}
		if (cmp == 0) return true;
		if (cmp < 0) high = mid - 1;
		else low = mid + 1;
	}
	return false;
}

__global__ void search_kernel(uint256 base_key, const SearchTarget* d_targets, int target_count, FoundHit* d_hits, int* d_hit_count, GPUResult* d_all_hashes, uint64_t total_work) {
	uint64_t idx = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
	if (idx >= total_work) return;

	uint256 private_key = base_key;
	add_uint256_uint64(&private_key, idx);

	ec_point_affine pub_key;
	scalar_multiply(&private_key, &pub_key);

	GPUResult res;
	hash160_compressed(&pub_key, res.compressed);
	hash160_uncompressed(&pub_key, res.uncompressed);
	hash160_segwit(res.compressed, res.segwit);

	if (d_all_hashes != nullptr) {
		d_all_hashes[idx] = res;
	}

	if (binary_search_targets(res.compressed, d_targets, target_count)) {
		int old = atomicAdd(d_hit_count, 1);
		if (old < 1000) {
			d_hits[old].private_key = private_key;
			d_hits[old].type = 0;
			for (int i = 0; i < 20; ++i) d_hits[old].hash160[i] = res.compressed[i];
		}
	}
	if (binary_search_targets(res.uncompressed, d_targets, target_count)) {
		int old = atomicAdd(d_hit_count, 1);
		if (old < 1000) {
			d_hits[old].private_key = private_key;
			d_hits[old].type = 1;
			for (int i = 0; i < 20; ++i) d_hits[old].hash160[i] = res.uncompressed[i];
		}
	}
	if (binary_search_targets(res.segwit, d_targets, target_count)) {
		int old = atomicAdd(d_hit_count, 1);
		if (old < 1000) {
			d_hits[old].private_key = private_key;
			d_hits[old].type = 2;
			for (int i = 0; i < 20; ++i) d_hits[old].hash160[i] = res.segwit[i];
		}
	}
}

// ==========================================
// STATIC C-STYLE TEST VECTOR SETS (COMPILER SAFE)
// ==========================================

struct TestPair {
	const char* private_key_hex;
	const char* p2pkh_c;
	const char* p2pkh_u;
	const char* p2sh;
	const char* bech32;
};

const TestPair TEST_SAMPLES[] = {
	{"c9aea24b8a2d9679d2aaaea98b61a397dc60db27bb90dfb4b168c4b86ae6e1de", "1GoVRapKw5yotnZr3ypHFFgHh1BT8YXn2u", "19RwGX2idJo2Unj3gJrkJ4LRRqt73ibPjf", "3QtB82xmHcmXz2nYarmWr18w8JPW2Rktdi", "bc1q442t7lhgmcr9cfetuc96nr5d2yvs3hlyengkwc"},
	{"18f1cc3fd411f53a6cbc7fcdf42ab1535baf4142e4cb1c8907a04204c27fe52c", "1NpGjxFxye6F9uvvsBpTGw4292MHVndqxN", "15sZ9DByvvmvHvyoLQeAKsWsR2HJ8YzVPG", "3DdtMnVZ5EnpsW3UbD74T5aiBLG3pqNTuT", "bc1qaa94fjey6yc0jfdxmrtt0an48mue50a634yfg2"},
	{"659de991216af620e47d177d21161639330bc3f609eb2f39c10e8b22ba55b2d3", "1ECEvQoerueecVZc4KK1tuEjKp2jefk8Ww", "1MwhQHqByznvGGDxrEXmt1ZwMETNGeLyer", "3NLzhQUaF4nLYRv5ZE3e3KH9cVsmQT6ixA", "bc1qjzuaf5dmmxljqpqthrmf7zenfyzkkg9mpt7hau"},
	{"b4e9e1b93970e2b2b42a3607fcb0dbba2761a5d1f0a8d72eb0940a6400a97a44", "18eZfnSgs64y17mCJMfQeeou2SF2SRWA9X", "1EkS56g6VyojAy4PqsBxhwrkueu1wgoELc", "3DfHYVg4vYd9i6q79sBVB3v9eFnousJm4L", "bc1q203c4g9v7kfsecs2fx04wf450e59gr6e9mnqc0"},
	{"9dfaa6260586bbb1347b1ece87222ea536906cbbf100cb6a478d0ed9aa2f3a05", "196nLQEXMhfqqR5KD6v7CZk1Wd9gTP5bNY", "1F269Zn3dGSXHBvVeXq3pa5ZBBcX5o6vMX", "3HsWuKCfczjHGmcvFvEVEUhihWgKWyG1ao", "bc1qtrvwmmdtm5uu70kuul3d0aa76k3u2e4xqmd7v4"},
	{"729cd01370637d2164ab6fa2505b5ae56044a653e161d4389c152de139ac91f8", "1NBM6qTkkwUrAU6E33ek8UAUZSma3cYKn1", "1FU4w5jXj7kcPShW513hebCTHX95BhCWCc", "3LuJkDJvT6UntS4WtUFpwScAKWfg3Uefqp", "bc1qap8efzvt88nuxrn67k4za28hhyhpn9ht0wf0wx"},
	{"7558b7ba0450e88e1a3d348f7ba027af77bd115ee5ae2a6865b92e4cffdf8ca7", "13MYWXxAD4cuUjGs8kFmKfkqRDX4dJM2L9", "1rMJJN8JY6c2y7zX4GA6cTRMXetpwRxMb", "3Fg3c1G3Y1aaEz5J4Zxo74FhDyRo29tqqU", "bc1qr8fdl9rutzg70gakd5qjjjhq8zh6zux4v3p2ct"},
	{"215a0a9bd78d30d6853165b04cc0e1fdc21045a67819cac1ed41f9991ea96b18", "1LqbvYgsgcqxLzvxiKgf9zkcUkhAWuzx7c", "1DfTs4MsEPf2NocNqH1MssPqm61doKbzau", "38MN5wYSFR5kQyYotR99CEQGSgbAY8VZnm", "bc1qmxdcytpuk3fkg5g35a6q7555tsug7k6lux70gd"},
	{"5460e4f2b2485d3797c1ce1703216a3dbc6fc62e5375f134c037ad39bfedcb20", "17BBTxDFxB9sajTVFWEu7ySW4czQGGyNr9", "1QGfZPgFjfzw5xqwGxnoJYTAPXG5AkuVke", "3HRgWiPBXRX3c7QVPNFSdLBJyEZvErYN9U", "bc1qgw76vktnveedrlxtw9tnuz6xyked2t49h0en82"},
	{"3150eecb94c4d7a3a91bb4b752436463ff98d101b4d7883cc3333c959fac9106", "18fna6wrf64wf8qPhUSFZQxr3o6yQkbqoU", "1614dVsjSUqYwfLWCzBDqYQYB1taH8Cu1d", "39bxqC7tbsioGN9QBLHJAheDmFw91KXCBL", "bc1q2s0t5sww3tpu7hcfj8ftn9yxx9paxsaee7yuqy"},
	{"d510b9af62133e73dbc6b3dde92e36f0f13a7c98e2ffc0fa5344d82b0d69ead1", "18kNfRW2CKt462GEtFjhXEPB7hrtUCKW1f", "1DA452XZPyc7pM5MPP4chQioyNxKK2YKH7", "3JMr7xo97PErYkywQVf6v8Bo3ExmqxMsgH", "bc1q2n7dnz2p2tu762pqq086xyrkpgj3m5y32uv4qa"},
	{"dcf561e9d4b010b71117972954b309c72e3e08b18724cc2f208f3cb8bc607b35", "19pwDp3fFG2Bv7EZuYdvBYJiKxmxF51SHh", "1MPAY9CQmw3eXweaKWTHoxXFsQkHjsa4LF", "3LpvoBxK4Zt9PXs8Ntf1eRmPsRHpjqt4zC", "bc1qvrgazknu58dknuxljh7j8mqlwdyml9cde5nqle"},
	{"6544869a5bd50818178f28fc63eb4dc3653ec555efcad51c0c5b57d749e63b2a", "1KyzsWFnK6sQgeE5ieCtZkz8TTEQdPG794", "1Jei82kiWBXgMeqU8wXMa9AYGpXDCsiGm7", "3PHxnMfm8tzBhVYoxrGvk2wbrRkMuTxFJn", "bc1q6quamdt6vqdvf94weupvnzrgrrqyv3suqu6cxm"},
	{"9c0cffb8aafdc6d92f24f400b56ce754845c3c2440314b7501bfc82bf843f13a", "14odBRvuRArdwRmqFaJ86KGxZYMAYwir65", "12MDmMzS6SFjsofeQJkYCXZB8pqFQKNUw2", "37wq9bxABvmjQAAqDNWAeqqYpqX9A5kEHT", "bc1q9xumdp59jnk4hsjm7e5v5gtrw8c90h84wx7upd"},
	{"12b17a30ac686f7f555b05e76b3c10d85d084a497b9a4cb73f4836afe3d7ced1", "1MJM1mHURE4hKLswHQtLuJT65D8NQPTXB6", "1HwzbL5WTz3PvUKR7GRMYbDsWfqE635y7r", "3KUVUwxkpNFdWw66Mt8Wv2Dby6j9RKeRrx", "bc1qm64ykrt5xxj7nyap25yxm3dmnetqc27ch63kex"},
	{"30d0b02dd93cb477680d4833e4b13b4cd87b7ed8a8e36dd38a887d62452e85cf", "13qA62uQDY2k2eX8r2Yvuwo7VvybrurABZ", "1F4VLoeeKnEucUztQTetpnzzywyYBz3zUe", "3KXXQEDvxxEU5tSfaUbJFbTP83mKSmoDZz", "bc1qru9umy94f0gs7u28dslcp2faptdudu8h3c6kn2"},
	{"d6602a5f9764b100821d22c1a914bb1ef932fd0dd3759023c2f14825f010165c", "1LVkzPyxy4fDAzfQTe1XtVmF1aNBD5Wnq4", "127ayyanQRgTg9ctscszMb3u5M3E36cgdi", "3KzXexrmfLwEX5KtKe7yx1hhhNEf1AHQ8y", "bc1q6hdvr6nrz6dlcekaknwqed9qpf574n5xa7qtqd"},
	{"b6a2eb91c8d07e194d6501c8eb65d6ec70757f59c12a380e22aacc898e49c5c8", "1NqDfDoHeSzUDGk1FTJ1wn5rbcd8DSukic", "17ccBT86dpHm6Pn5FsB7vaUdpRL73oqCJC", "3EM8BV16nFaG3xcioZ1fngC7H8vo5EQH3q", "bc1qaaujesp9286mvek8flsvlq30dchn08efg9eqt0"},
	{"4322f3b9b38a1ee972c8f8d1a63e883137749894fe10e27be2c98dc2c36fb440", "1Gt8XYZLUtwAMkQ2aqGSCPJq81kWQGhYu6", "1K1E18uTWEkMiqQjriTBKJYk678mLDFTFs", "35G542mocQ8kYtvzm1PrjBZqxCcUs3Xxmm", "bc1q4c6kywenvmwsanxfz0h4dkrh3pxramsxqyjxny"},
	{"b3a2af1ee74fdfdf38a65cf3c3aee30d743bac3d8e547c9e2cd0ddd56352c5d3", "1DM1BWLiiVKYiWcbCH7Eg5xJKzTvuGoTTD", "1NxK7tpZ2Kk4WgqEKTZyG2dmQTp1texWCN", "37dWCMRR8Y53VLShS6UJLKXfZMqMqU3Z8h", "bc1qsa5l44exuadwp2s9n0njljremxgwjz0lc5a9x4"},
	{"dc2796a119b2293ad5a174c8ce33e09a4cc867f069116d8d58df728097eefdbd", "1FeTDP77ozss2hRYGY1XfQZ6CrAXgst4Kg", "1Bom9ZaqnHg3ejn6rZYB51N2PPDePU6PNV", "3C5bkJ6XdWhcjabzaiwXa1ULauDnZApXUn", "bc1q5zns3yx4slgw382rfrmeknfjns706u3lxh2dw0"},
	{"74d65f86450198f6994ca3866d2394e4a79e4c890e6de1faf485a3d66d24c0e0", "1CdpfS88dbcdKDDQs6N479dWTbhcjnbdEP", "1AQmLmi4ULAtm5w5NouSbc2vtzt5jAh8L7", "3Qp3KxZRZmkJUiVvWVXtWYbfo5ezwLjmUu", "bc1q07sz28awh5mfvscgwywq8rvyl99ttur2k07tk0"},
	{"b2aa7fe4fbd0e80cdd867732a11c05b93d6d5070e4e6765ab43dd8733d8a6a00", "1P7PAkZ3TyTCh4R45kwqngCMYroe2cDnCV", "13v7Ywyc4dRiDdR87bSGDd5Bk3Rxjtw9D1", "3D1aMEiYdSMJKJzGg5BPht9oZWFGUXJSSY", "bc1q72ruf8tk67juzz5avcdt2h4fevjg0h05yhgqys"},
	{"60c97fd834dadd1ba31153907687682573330e73cbb92ce1f5871a30b9b65f80", "14tLy54edbBr1CAdhmMjm1rtR5cxBqB41J", "13oyGUp3EbfzhDLQy5hFbicRYmLBd68vXK", "3H1nfNcdJTutbMxh1QHMtinEDxFYMXc2H5", "bc1q920yy07qrkfwaup5qc5p7tkxz03sghu5jjm2gq"},
	{"2e6212f56cd11fb4632cf00c85c072426c1575e90092c467060048b896c9fc10", "17kD2AeY28mYgBHyRy6bMY7FanAtodZXJ4", "14JMQkhM11ELS5EEox7k3Z24E5Pzm4D8Vs", "388yhFFGg57AYFiF2wzmboy5zkEruSvYMT", "bc1qf872ej84mufkz5js4xdc0dt8p4jm8y4233aakn"},
	{"d750136fa45ac48814a16a94c0d8d3e1721e2c6dd8053abd423e9c0c0513c3b3", "1HudXJAFPynA1y1aHnVB6vJdvaes1BMtdZ", "1JPHXTNSUCQuwrLLxUzVvZa5Se7t9wjDG5", "3PKGBin3JPymXJo4uiDbps3XxV8Ymno2am", "bc1qh9mzz0eq36pc9rvxjq4rw3wacf7uw8whu0wgpk"},
	{"8ca8f56368ca7359b33b6eecb9c97b2ee4ca7313474f81f73eefb68f94da3896", "1DKWvi4oUWTsmC37jiPpczG5B1j1xxaCEP", "1MKLiqRB4LZhh4FMeepH4WDBvwXk7U4R5n", "38FhnPReSCU9sXJJDCxPify3M7Etu44HRG", "bc1qsusl5jvt9m7j77tkjmlv028ezmu6wes8svg9k0"},
	{"2aa3367571509dd28661fe2b891d89afde70b8bcf04dcd78b8f2caa4969cdb1f", "16cQfnrfYPYKAG6DXtHWnG38uTyAachXxU", "136HCTxhZDSaWzkDtsP8Jud76EocmhLd1Q", "3QYVTQUrDmCYqrihnX3SHUpygCN5919gvS", "bc1q8k90rlm3s4a35dx50027ggfjkfr6258fmecxec"},
	{"8dab3a5fe93c41c1e9d509f749b71ccdeccc2be1163a7656f15d9f69e0628ee9", "1CVVS1woZCMigBdENeEAcyyFVh6PRx5bEm", "1Nqh6AN7x1FHCBgjSaMCKJsDLbMbG7quf7", "3F1Lty8wV6bJ5eZuZo6MLuZFNd7WFHgaGF", "bc1q0cxv8zvugy4l455fjut05h7ugfu6ds88zlfeva"},
	{"816c965608047795e91bef901a545af0c238ba5d9ffb00430799048033800cac", "1KoXcTZieDiHBaH1oTw1VZDdwrLJ7bJLnH", "1GqMRAGRzgX2YRvhMQMbrgBbmxC2bfm6FM", "3HpGGGp14KKz9aEWTZkrVC1ZvGuQBMkrCM", "bc1qecl08rlq48jznxhxuzjd7sl0uqcwd3z4gjfddm"},
	{"f6f743bf564058cca357471c8fb5ee54d79956e4e420a30805c88f5fbd5ce63c", "15onWi3zh2N2sNn1NqSEgxpEfhqEoSNbKA", "1PPPBqetwYBa2gZHVYUmyvudzF9P2X6hLp", "35L1oG26PB7zSGnysnLWuPQCzG93n3j9Xu", "bc1qxju6zzvrsgkale96hkgcm6ntyglt5nqr8527kv"},
	{"883c973092479202cfa179b10ea6c909e27d564fc149b2a79dd13eba2cb1379f", "1FwjzzpfcJWd2bUJBBPUtMCvNdrZoRRY7X", "1JRW4nwhvfSYZywoau287zYcjpJppmxw43", "32FisBVcJT2HwH9731qTmDuXsQzv78bKCJ", "bc1q50kpuyd5dlv7xqcuf5w628t6cxtuc4sk7yc8a4"},
	{"ef1da1787a40310a7d3013a36e788580ce83a109c6daa5436117a68dc8724e34", "1PqRmMfntVKxYrGmnxqTGrB8eTg8NNa5nF", "1Ms2Pkz3K5xTk9v24oGKt5mQSfm87aGBEk", "3B2uWimR6F1rUsC5npxq8utkaaNij8XxRr", "bc1qlfak0mejyaska7vxrdwx6ppknnxx5ucae97v8r"},
	{"eef0ca84b38802da42e589790babe3ffbbfe09d3884d6ebcdec90a399108fa61", "1JqQLJRdyVs7SzyHsyMktdU2LBwRWdw3se", "1GZV9yeqAnQvmZrYmCFfvu5zF1LR1Wf1f6", "3BcZRVTwKe4ZRqopLegr6aNvyWjZAUNqeP", "bc1qcwsef6nsuk72qwwnnwkjwesnjf9e89gpw5h3e2"},
	{"c90e17b4a99477aa21899abc383e8b76cb579f2e18e2e85143099dc58c01dd59", "1BazCTPLd85EzifEHQ7HyyExvPHwbgGj5h", "18bW6DZ3FTjLDjmxHpuA2eUu2YwT9vw9UH", "33NzDADh6rauawSAJX3A1ody3quPxLYwyP", "bc1qws0tkzm7jcnpdn6mh7ekxl8e38u5dprgcat4ap"},
	{"b27a2700d4136d198fbba8f5d088455d0741d401a912e8ecf1347a5acc1b9868", "1978CD8SPJBBrDTgXhrwPgWHBsRqBxxcVt", "162SCbhY4aiqFpMidTsySMuMCpYtChguRB", "3N489pRRgN4LHzzkcU8iCvX6uLGGAxreMS", "bc1qtr5crd2gwsjmlh4mvwse8rknk4nwkvz3099fml"},
	{"47c1b9da9a12c2d5eb5a1d10b3d6b5bd77d76ae76a7bfd0ef80f3c621a600523", "139ojckRFsg5NXaTBj7zGceLWNHNDgok1Q", "1CsJSACB4HBt3WGPCaB6z87UBySG4Dnwig", "3Kb9qgvBf1Rb2ABsDDUvX4YALhUdyYuMpN", "bc1qz7dfw6eg9pt70ze3nty7lnhw9fte8znp2ef25s"},
	{"876a6ef34db1d93fb005da7b0059555287437da984711d389f30199960a0a343", "1PsNBvm2YnivFyzC3fAkMYRzehPSWpaiAc", "1N49z8afb6YHaLX5feuLqCR3q4Gf1KVPPz", "3NjcsobmqmubDEABL3avyeX25Fee9PTpi2", "bc1qltv5pf96edul6hchemr8e8r2j764p5eufhjwgy"},
	{"cc24249695eb0978252eb23a43b9ba4ff46e47783a5e010077943b5abba85edc", "19sekNoW71g6BX2My2faw2gxvk2z8gSFRk", "1MHkqwA1aWAjRnyWTV8eaEfaBcb68iT7FD", "3BLpXbQu6iuyN2wTXTL8JdgwgjwuuFRsa9", "bc1qv924pr6vzxc8s5f5tv0pgnrwpk730ean2ra3p3"},
	{"96adc55323e7adcb5df650b8900b157242ccddbe64b74d01b34be82bac117faa", "1FPScFsWmQa8e6mpqFhiQxmw377pMigC3f", "19UcYKV8VHboz447BpLeweGCQKuwLQuW8P", "39Jki7jnEsn1xVnQ9YiYYLhj2ZvFMEgjEC", "bc1qnhgynkm3wpyj5d3v7gr3ke5s29ytwnwgksjkm9"},
	{"daf589abf2038457b0c6e628dd1eae7af8559f7e0aad60d76413174ad7d4101d", "1CcHT7eu9HYSUziwYhm9o4wFEdE2q68gJx", "1Ag93sBYj39MbXw6dU52hzmxfNMQD664my", "3PjY6Eba5iBiEmhwsZYqNyjPCJe6A88NT2", "bc1q0a26e8yhaql7eu5c688n2ds67wujgqcpt4t67e"},
	{"fc36f79768104df7b94c5daaadca37784a9063a3cf0b305961bb1750d319c497", "13An8AgCoAhvzwznKoKjTEvqsuqnjc9xgM", "1k5N3epcqgY4uBdXt5P5BWKEY4QSEGUj1", "3N17RCucFaEMxbg6SnmTdfwbA7z6YDMB7C", "bc1qzly6nxzr4e8zvlw5spgnhfws6y6x3qqpput9fk"},
	{"6781d7a1a0ff6a25b03dd32abf19b68981aed2ed5bc9a7e61d503de5a351c203", "1Dv6acUMA3bJLsjvtqTsCN1S57xj16QzLs", "1thoZeFAQDnVtCiyjF64uwVeKHhbzDZXb", "3CqXxnSSAot3jqfT9cuu1yqciKhePxfCgA", "bc1q3kkrdq044q58ruwhqpgtegnr60fehs534uke3r"},
	{"77b82b4de0b4b04b17c2a86ac405012012f144334a41b3c27a1ccf5e438a13da", "1MSY1iXuBhFjXTip4wQxiBissJvuoYhqnG", "1FUq2pvr7QjnEtX6W6tp9vKMs5ct7cwaEr", "3LMWfP6oZYscTs1hkd9BmeXbJaonpSL6Dm", "bc1quqmv6u3f0m6980ky7az27w9ccqermuc4hx4s9d"},
	{"019b6a3e01d7cebd39f828473db6cedf20905165907b4ce60ac141024108e15e", "17Lv3FNT2NFtj6djeBk8BSiXFWkCgwKw6C", "1MDhyqjeiYGCCy84zqPEELzkapYGhHGRXc", "3GDJ7hGckRhT2EWjyMxNdeSbTS2N87o6Bi", "bc1qgk2wawzyg4ttfhch6ge6fgqz27slxketrf38nx"},
	{"a790b9460e2dfcdf4406a90856d8daa2f043bab43d494de313ce0f6e5efccd78", "1LvchWqkNPWRATfuHCwAEqtwcBAJTC6ZUa", "14RvkKfxfRt6jmxQRu2umdsqbepYEfbs1T", "3GyB31R6VF8BWFeW88zZGDShn2Dh2ybeST", "bc1qm28rcjtff2z3unnva68rf374c4g9vr56p243gg"},
	{"34ddd04390b300bdc9b5f4ca4d2ffa5c77f9408022b3684958c7605cf90ff8d4", "1CGJpPdTHuWwfuMTWgagAFCDC6NBk2fUp4", "18Fq8JQ9kp7v9znc3fAFhvDw5X7hrEkkre", "31uaVkWsqevqpsUoZi56cU652qkNvRN6JW", "bc1q0w88a7f7cjmt3u3pjh532qr27zajr3qwdh4q28"},
	{"7326efbcc29102be232ee3d4262e1c5aaacb26e1e5fda165f6601c671e23c025", "1DjQNe61Mu47pD7xGri2Kn4enYnXCUJFRq", "1KmninWTdJc6SeuqLxhGocB5rgFEAHrhyP", "31nyeZbaxULki9x9RfvTf1Dimkk5jzQiL2", "bc1q3wn8m88kj72wvz3l9xmlhldzdv0q2p3mwc82al"},
	{"3cd9881e7ed27099c6700a06017bb9236dc62006da6e58c574c5dad4f7392456", "13GBkBKNeobJYDmUXcJwCbu78HPFQRbH8E", "12vKrjXYTYivUGrAiHAZM4vj8bkRCCfgb3", "35GZp1Dbb75DwFP7t4AZqD8fhPhn65KoV5", "bc1qrr8htshemx9wgx75y2h4ap5gsmguntd87rdree"},
	{"31367233287608767ef9dbc30af5386a0c09e97d97f9ebbba2562ac9310b4599", "19b9QSkGbD3G3dDH2YX6r2RV4xwfkks2Ck", "1GCSbossgqTVeQbmba44o8dsebf4xsirim", "3EzK9qwT1c4UC4UYyLM1vhX1SHnY5uYLum", "bc1qtcmz5x2x6xzktqxql89mdwqhvwacjn8vaxe0mg"},
	{"d4ad4a59f14c44eb460c7638ba26755fb3ad8e14ccd04f2a0a92388debb40c8e", "1PuDHRZydkvm6pa5UK5Uwj8g7G3uuMEHUA", "197BgSqD3gghVEDrGJE4N2VhHe6hnC8AF9", "3GMjPYujH1NABr2YrFfYUQsooGDUq4nVLq", "bc1qlve2d90lhs4cdujl3r9yujr8l3ajzuam95fpjj"},
	{"bbea6496bd69be47a69d9ba12326b3f5d7cbc05249f117ac641f2149e943100a", "1CCjD7SELdvSz6T9N1vpTmhw83p97KNbk2", "1Baxmyo1eB8GUQUhtx31X6BXgYuPkxxZ7r", "3MxTnMyXMEE7cXg6mkLgEsPuMSBxDY69SQ", "bc1q0tsnzlkts4naqt4meuvae9qxxnpu9ndtdnmgsq"},
	{"09c41e4d6a78c7b9e85a0b8f9d92e94402e955dd847f2f27aa06cbe5ade1297e", "1MFepJJPDTf3RgVJtRVHu1Q9ZFZjzw9xZP", "1MPRZgs5qVujFkR3cwYFtxiHGdz9KsjfzG", "3DG7nK4tb5sjfENa6wJjryHJT7ZH8KYcUn", "bc1qmcn706judfwjt2jwpqltrlkhww7cfptnf8h978"},
	{"6425b272febfb7098e6233927d578844d2e964d7429d88374d6c53f485c2f997", "13D6oeh3xDP8Gu1w4tKEQXDrZjVMrXeBy9", "1B3TPZFzkLguc2o4AdC2x2H2MG9pomtMbG", "38TB2czAGbRCySwaykEAFBxPFvjnkrxBt3", "bc1qrqapdxhyrl3rhvy0uplq83nvzn9dhx74q85r60"},
	{"f10dc8cabdf931c7c5d62550e6fc8b233e0dfe12850e324166aa09183d131c89", "1CZ8F7q4L9kV2fkMEcZPwS5yjwTEo2VPcX", "1MJNQCNvfoYc3CRzRaEpUumkVQo7LF9J9S", "3KcvX6kQJH5VJ8bs6kh4C7ksNwswDdJo6b", "bc1q067tm2c7ws2ak6nts4xrsqj70n9hw4szkkuu34"}
};
const size_t TEST_SAMPLES_COUNT = sizeof(TEST_SAMPLES) / sizeof(TEST_SAMPLES[0]);

// ==========================================
// PARALLEL CPU PATTERN MATCHING WORKER
// ==========================================

void check_patterns_parallel(const std::vector<GPUResult>& hashes, const std::vector<std::string>& partial_patterns, uint256 base_key, const std::string& found_path) {
	unsigned int num_cores = std::thread::hardware_concurrency();
	if (num_cores == 0) num_cores = 4;

	std::vector<std::thread> workers;
	uint64_t chunk_size = hashes.size() / num_cores;

	for (unsigned int t = 0; t < num_cores; ++t) {
		uint64_t start_idx = t * chunk_size;
		uint64_t end_idx = (t == num_cores - 1) ? hashes.size() : (start_idx + chunk_size);

		workers.push_back(std::thread([start_idx, end_idx, &hashes, &partial_patterns, base_key, found_path]() {
			for (uint64_t idx = start_idx; idx < end_idx; ++idx) {
				std::string addr_c, addr_u, addr_sh, addr_b32;
				bool c_init = false, u_init = false, sh_init = false, b32_init = false;

				for (const auto& pattern : partial_patterns) {
					bool match = false;
					std::string matched_addr = "";

					// Performance optimization: evaluate address types lazily based on prefix match rules
					if (pattern.front() == '1') {
						if (!c_init) { addr_c = base58check_encode(0x00, hashes[idx].compressed); c_init = true; }
						if (!u_init) { addr_u = base58check_encode(0x00, hashes[idx].uncompressed); u_init = true; }
						if (addr_c.compare(0, pattern.size(), pattern) == 0) { match = true; matched_addr = addr_c; }
						else if (addr_u.compare(0, pattern.size(), pattern) == 0) { match = true; matched_addr = addr_u; }
					}
					else if (pattern.front() == '3') {
						if (!sh_init) { addr_sh = base58check_encode(0x05, hashes[idx].segwit); sh_init = true; }
						if (addr_sh.compare(0, pattern.size(), pattern) == 0) { match = true; matched_addr = addr_sh; }
					}
					else if (pattern.size() >= 4 && pattern.substr(0, 4) == "bc1q") {
						if (!b32_init) { addr_b32 = bech32_encode(hashes[idx].compressed); b32_init = true; }
						if (addr_b32.compare(0, pattern.size(), pattern) == 0) { match = true; matched_addr = addr_b32; }
					}
					else {
						// Fallback substring search
						if (!c_init) { addr_c = base58check_encode(0x00, hashes[idx].compressed); c_init = true; }
						if (!u_init) { addr_u = base58check_encode(0x00, hashes[idx].uncompressed); u_init = true; }
						if (!sh_init) { addr_sh = base58check_encode(0x05, hashes[idx].segwit); sh_init = true; }
						if (!b32_init) { addr_b32 = bech32_encode(hashes[idx].compressed); b32_init = true; }

						if (addr_c.find(pattern) != std::string::npos) { match = true; matched_addr = addr_c; }
						else if (addr_u.find(pattern) != std::string::npos) { match = true; matched_addr = addr_u; }
						else if (addr_sh.find(pattern) != std::string::npos) { match = true; matched_addr = addr_sh; }
						else if (addr_b32.find(pattern) != std::string::npos) { match = true; matched_addr = addr_b32; }
					}

					if (match) {
						uint256 matched_priv = base_key;
						host_add_uint256_uint64(&matched_priv, idx);

						std::lock_guard<std::mutex> lock(results_mutex);
						printf("\n!!! PARTIAL PATTERN MATCH DETECTED !!!\n");
						printf("  PATTERN: %s\n", pattern.c_str());
						printf("  PRIVATE KEY: "); print_hex_256(matched_priv);
						printf("\n  MATCHED ADDRESS: %s\n\n", matched_addr.c_str());

						// Save to found.txt (append only)
						std::ofstream out_file(found_path, std::ios::app);
						if (out_file.is_open()) {
							out_file << "Pattern: " << pattern << "\n";
							out_file << "Private: ";
							for (int w = 7; w >= 0; w--) {
								out_file << std::hex << std::setw(8) << std::setfill('0') << std::uppercase << matched_priv.v[w];
							}
							out_file << "\nAddress: " << matched_addr << "\n\n";
							out_file.close();
						}
					}
				}
			}
			}));
	}

	for (auto& worker : workers) {
		worker.join();
	}
}

// ==========================================
// ENTRY EXECUTION
// ==========================================

int main() {
	cudaError_t cudaStatus = cudaSetDevice(0);
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "cudaSetDevice failed.\n");
		return 1;
	}

	// Start Tamper-Proof entropy pregeneration background thread
	std::thread pregen_thread(pregen_worker);

	// =========================================================
	// STEP 1: VERIFY ENTIRE STACK INTEGRITY AGAINST TEST VECTORS
	// =========================================================
	printf("========================================================\n");
	printf("[1/3] VERIFYING HARDWARE STACK AGAINST CRITICAL TEST SAMPLES...\n");
	printf("========================================================\n");

	GPUResult* d_test_out = nullptr;
	cudaMalloc((void**)&d_test_out, sizeof(GPUResult));

	bool stack_verified = true;
	for (size_t i = 0; i < TEST_SAMPLES_COUNT; ++i) {
		uint256 test_key = hex_to_uint256(TEST_SAMPLES[i].private_key_hex);

		run_test_kernel << <1, 1 >> > (test_key, d_test_out);
		cudaDeviceSynchronize();

		GPUResult h_res;
		cudaMemcpy(&h_res, d_test_out, sizeof(GPUResult), cudaMemcpyDeviceToHost);

		std::string b58_compressed = base58check_encode(0x00, h_res.compressed);
		std::string b58_uncompressed = base58check_encode(0x00, h_res.uncompressed);
		std::string b58_segwit = base58check_encode(0x05, h_res.segwit);
		std::string native_segwit = bech32_encode(h_res.compressed);

		bool pass = true;
		if (b58_compressed != TEST_SAMPLES[i].p2pkh_c) pass = false;
		if (b58_uncompressed != TEST_SAMPLES[i].p2pkh_u) pass = false;
		if (b58_segwit != TEST_SAMPLES[i].p2sh) pass = false;
		if (native_segwit != TEST_SAMPLES[i].bech32) pass = false;

		if (!pass) {
			printf("[FAIL] Verification Index %zu failed expected targets.\n", i);
			printf("  Expected C:  %s | Got: %s\n", TEST_SAMPLES[i].p2pkh_c, b58_compressed.c_str());
			printf("  Expected U:  %s | Got: %s\n", TEST_SAMPLES[i].p2pkh_u, b58_uncompressed.c_str());
			printf("  Expected SH: %s | Got: %s\n", TEST_SAMPLES[i].p2sh, b58_segwit.c_str());
			printf("  Expected B32:%s | Got: %s\n", TEST_SAMPLES[i].bech32, native_segwit.c_str());
			stack_verified = false;
		}
		else {
			printf("[PASS] Sample %zu correctly validated.\n", i);
		}
	}
	cudaFree(d_test_out);

	if (!stack_verified) {
		fprintf(stderr, "\nStack verification failed. Search execution halted.\n");
		stop_pregen_thread = true;
		pregen_thread.join();
		return 1;
	}
	printf("\nINTEGRITY CONFIRMED: Hardware calculations match exact specification.\n\n");

	// =========================================================
	// STEP 2: GENERATE AND PRINT 20 SAMPLE PRIVATE KEYS & ADDRESSES
	// =========================================================
	printf("========================================================\n");
	printf("[2/3] GENERATING 20 LIVE SYSTEM TESTING SAMPLES...\n");
	printf("========================================================\n");

	GPUResult* d_sample_out = nullptr;
	cudaMalloc((void**)&d_sample_out, sizeof(GPUResult));

	for (int idx = 0; idx < 20; ++idx) {
		uint256 sample_priv_key = get_rotated_key();

		run_test_kernel << <1, 1 >> > (sample_priv_key, d_sample_out);
		cudaDeviceSynchronize();

		GPUResult h_res;
		cudaMemcpy(&h_res, d_sample_out, sizeof(GPUResult), cudaMemcpyDeviceToHost);

		std::string sample_c = base58check_encode(0x00, h_res.compressed);
		std::string sample_u = base58check_encode(0x00, h_res.uncompressed);
		std::string sample_sh = base58check_encode(0x05, h_res.segwit);
		std::string sample_b32 = bech32_encode(h_res.compressed);

		printf("SAMPLE #%d:\n", idx + 1);
		printf("  PRIVATE KEY: "); print_hex_256(sample_priv_key); printf("\n");
		printf("  P2PKH (C):   %s\n", sample_c.c_str());
		printf("  P2PKH (U):   %s\n", sample_u.c_str());
		printf("  P2SH:        %s\n", sample_sh.c_str());
		printf("  BECH32:      %s\n", sample_b32.c_str());
		printf("--------------------------------------------------------\n");
	}
	cudaFree(d_sample_out);

	// =========================================================
	// STEP 3: DATABASE PATH SELECTION & INITIALIZATION
	// =========================================================
	printf("\n========================================================\n");
	printf("[3/3] SETTING UP DATABASE LOOKUP PATHS...\n");
	printf("========================================================\n");

	std::string db_path = "database.txt";
	std::string found_path = "found.txt";
	bool run_search = false;

	std::ifstream test_db(db_path);
	if (!test_db.is_open()) {
		printf("[INFO] Default 'database.txt' not found.\n");
		printf("Choose execution mode:\n");
		printf("  1. Run in Benchmark-only mode\n");
		printf("  2. Specify custom database file path\n");
		printf("Enter selection (1 or 2): ");

		std::string selection;
		std::getline(std::cin, selection);

		if (selection == "2") {
			while (true) {
				printf("Enter database file path (e.g. C:/data/database.txt): ");
				std::getline(std::cin, db_path);
				std::ifstream custom_db(db_path);
				if (custom_db.is_open()) {
					custom_db.close();
					run_search = true;
					break;
				}
				else {
					printf("[ERROR] File could not be opened. Please verify path and try again.\n");
				}
			}
		}
		else {
			printf("[INFO] Benchmark mode selected.\n");
		}
	}
	else {
		test_db.close();
		run_search = true;
	}

	// Determine output file path
	if (run_search) {
		printf("\nEnter destination path for matches (e.g. C:/data/found.txt)\n");
		printf("[Press ENTER to save 'found.txt' next to database file]: ");
		std::string output_selection;
		std::getline(std::cin, output_selection);

		if (output_selection.empty()) {
			std::string dir = get_directory_path(db_path);
			found_path = dir + "found.txt";
		}
		else {
			found_path = output_selection;
			size_t ext = found_path.rfind(".txt");
			if (ext == std::string::npos) {
				if (found_path.back() != '/' && found_path.back() != '\\') {
					found_path += "/";
				}
				found_path += "found.txt";
			}
		}
		printf("[INFO] Matches will be written to: %s\n", found_path.c_str());
	}

	std::vector<SearchTarget> complete_targets;
	std::vector<std::string> partial_patterns;

	if (run_search) {
		std::ifstream db_file(db_path);
		if (db_file.is_open()) {
			std::string line;
			while (std::getline(db_file, line)) {
				line.erase(0, line.find_first_not_of(" \t\r\n"));
				line.erase(line.find_last_not_of(" \t\r\n") + 1);
				if (line.empty()) continue;

				uint8_t target_hash[20];
				uint8_t target_type = 0;

				if (parse_address_to_hash160(line, target_hash, &target_type)) {
					SearchTarget target;
					memcpy(target.hash, target_hash, 20);
					complete_targets.push_back(target);
				}
				else {
					partial_patterns.push_back(line);
				}
			}
			db_file.close();
			printf("Loaded %zu Complete Targets and %zu Partial Search Patterns.\n",
				complete_targets.size(), partial_patterns.size());
		}
	}

	if (!complete_targets.empty()) {
		std::sort(complete_targets.begin(), complete_targets.end(), compare_targets);
		auto last = std::unique(complete_targets.begin(), complete_targets.end(), [](const SearchTarget& a, const SearchTarget& b) {
			return memcmp(a.hash, b.hash, 20) == 0;
			});
		complete_targets.erase(last, complete_targets.end());
	}

	SearchTarget* d_targets = nullptr;
	if (!complete_targets.empty()) {
		cudaStatus = cudaMalloc((void**)&d_targets, complete_targets.size() * sizeof(SearchTarget));
		cudaMemcpy(d_targets, complete_targets.data(), complete_targets.size() * sizeof(SearchTarget), cudaMemcpyHostToDevice);
	}

	FoundHit* d_hits = nullptr;
	int* d_hit_count = nullptr;
	cudaMalloc((void**)&d_hits, 1000 * sizeof(FoundHit));
	cudaMalloc((void**)&d_hit_count, sizeof(int));
	cudaMemset(d_hit_count, 0, sizeof(int));

	// Allocate GPU results buffer if partial patterns need to be mapped back to host
	GPUResult* d_all_hashes = nullptr;
	int threads_per_block = 256;
	int blocks = 4096;
	uint64_t total_batch_size = (uint64_t)blocks * threads_per_block;

	if (!partial_patterns.empty()) {
		cudaMalloc((void**)&d_all_hashes, total_batch_size * sizeof(GPUResult));
	}

	// ==========================================
	// INITIALIZATION & SEARCH RUN LOOP
	// ==========================================
	uint256 base_key = get_rotated_key();


	///  UNCOMMENT FOR TESTING PURPOSES ONLY and also uncomment the while block below and then comment the real while block also put the addresses in the patterns database:

	/*
	base_key = hex_to_uint256("816c965608047795e91bef901a545af0c238ba5d9ffb00430799048033800cac");
	host_add_uint256_uint64(&base_key, -2000);
	*/


	printf("\nStarting execution search using base key:\n  ");
	print_hex_256(base_key);
	printf("\nLaunching loops (1,048,576 keys per batch). Press Ctrl+C to terminate.\n\n");

	uint64_t accumulated_keys = 0;
	auto execution_start = std::chrono::high_resolution_clock::now();
	auto rotation_start = std::chrono::high_resolution_clock::now();

	std::vector<GPUResult> h_all_hashes;
	if (!partial_patterns.empty()) {
		h_all_hashes.resize(total_batch_size);
	}



	///  UNCOMMENT FOR TESTING PURPOSES ONLY:

	/*

	while (true) {
		// Execute 33-Second Key Rotation from Pre-generated queue
		auto current_time = std::chrono::high_resolution_clock::now();
		std::chrono::duration<double> rotation_dur = current_time - rotation_start;
		if (rotation_dur.count() >= 33.0) {
			base_key = get_rotated_key();
			rotation_start = std::chrono::high_resolution_clock::now();
			printf("\n[ROTATION] Private key space securely rotated (33 seconds elapsed).\n");
			printf("New Base Private Key: ");
			print_hex_256(base_key);
			printf("\n\n");
		}

		// 1. Launch search immediately using current base_key (starts at base_key + 0)
		search_kernel << <blocks, threads_per_block >> > (base_key, d_targets, (int)complete_targets.size(), d_hits, d_hit_count, d_all_hashes, total_batch_size);
		cudaDeviceSynchronize();

		// 2. Check Exact Target Matches
		int h_hit_count = 0;
		cudaMemcpy(&h_hit_count, d_hit_count, sizeof(int), cudaMemcpyDeviceToHost);
		if (h_hit_count > 0) {
			std::vector<FoundHit> h_hits(h_hit_count);
			cudaMemcpy(h_hits.data(), d_hits, h_hit_count * sizeof(FoundHit), cudaMemcpyDeviceToHost);

			std::lock_guard<std::mutex> lock(results_mutex);
			printf("\n!!! TARGET ADDRESS MATCH DETECTED !!!\n");
			for (int i = 0; i < h_hit_count; ++i) {
				std::string hit_addr = "";
				std::string alt_addr = "";

				if (h_hits[i].type == 0) {
					hit_addr = base58check_encode(0x00, h_hits[i].hash160);
					alt_addr = bech32_encode(h_hits[i].hash160);
					printf("  MATCH TYPE: Compressed Derivation (P2PKH / Bech32)\n");
					printf("  PRIVATE KEY: "); print_hex_256(h_hits[i].private_key);
					printf("\n  P2PKH Address:  %s\n", hit_addr.c_str());
					printf("  Bech32 Address: %s\n\n", alt_addr.c_str());
				}
				else if (h_hits[i].type == 1) {
					hit_addr = base58check_encode(0x00, h_hits[i].hash160);
					printf("  MATCH TYPE: Uncompressed Derivation (P2PKH)\n");
					printf("  PRIVATE KEY: "); print_hex_256(h_hits[i].private_key);
					printf("\n  P2PKH Address:  %s\n\n", hit_addr.c_str());
				}
				else if (h_hits[i].type == 2) {
					hit_addr = base58check_encode(0x05, h_hits[i].hash160);
					printf("  MATCH TYPE: Nested SegWit Derivation (P2SH-P2WPKH)\n");
					printf("  PRIVATE KEY: "); print_hex_256(h_hits[i].private_key);
					printf("\n  P2SH Address:   %s\n\n", hit_addr.c_str());
				}

				// Save to found.txt (append only)
				std::ofstream out_file(found_path, std::ios::app);
				if (out_file.is_open()) {
					out_file << "Direct Target Hit | Match Type: " << (int)h_hits[i].type << "\n";
					out_file << "Private: ";
					for (int w = 7; w >= 0; w--) {
						out_file << std::hex << std::setw(8) << std::setfill('0') << std::uppercase << h_hits[i].private_key.v[w];
					}
					out_file << "\nAddress: " << hit_addr;
					if (!alt_addr.empty()) {
						out_file << " (Alternative Bech32: " << alt_addr << ")";
					}
					out_file << "\n\n";
					out_file.close();
				}
			}
			cudaMemset(d_hit_count, 0, sizeof(int));
		}

		// 3. Check Partial/Vanity Patterns
		if (!partial_patterns.empty()) {
			cudaMemcpy(h_all_hashes.data(), d_all_hashes, total_batch_size * sizeof(GPUResult), cudaMemcpyDeviceToHost);
			check_patterns_parallel(h_all_hashes, partial_patterns, base_key, found_path);
		}

		accumulated_keys += total_batch_size;
		auto current_time_loop = std::chrono::high_resolution_clock::now();
		std::chrono::duration<double> current_dur = current_time_loop - execution_start;
		if (current_dur.count() >= 5.0) {
			double rate = (double)accumulated_keys / current_dur.count();
			printf("[Active] Checked %llu keys | Speed: %.2f MKey/s\n", accumulated_keys, rate / 1000000.0);
			accumulated_keys = 0;
			execution_start = std::chrono::high_resolution_clock::now();
		}

		// 4. Increment base key at the end of the batch loop
		host_add_uint256_uint64(&base_key, total_batch_size);
	}
	*/
	
	///  THE REAL VERSION: 
	

	while (true) {
		// Execute 33-Second Key Rotation from Pre-generated queue
		auto current_time = std::chrono::high_resolution_clock::now();
		std::chrono::duration<double> rotation_dur = current_time - rotation_start;
		if (rotation_dur.count() >= 33.0) {
			base_key = get_rotated_key();
			rotation_start = std::chrono::high_resolution_clock::now();
			printf("\n[ROTATION] Private key space securely rotated (33 seconds elapsed).\n");
			printf("New Base Private Key: ");
			print_hex_256(base_key);
			printf("\n\n");
		}

		host_add_uint256_uint64(&base_key, total_batch_size);

		search_kernel << <blocks, threads_per_block >> > (base_key, d_targets, (int)complete_targets.size(), d_hits, d_hit_count, d_all_hashes, total_batch_size);
		cudaDeviceSynchronize();

		// 1. Check Exact Target Matches
		int h_hit_count = 0;
		cudaMemcpy(&h_hit_count, d_hit_count, sizeof(int), cudaMemcpyDeviceToHost);
		if (h_hit_count > 0) {
			std::vector<FoundHit> h_hits(h_hit_count);
			cudaMemcpy(h_hits.data(), d_hits, h_hit_count * sizeof(FoundHit), cudaMemcpyDeviceToHost);

			std::lock_guard<std::mutex> lock(results_mutex);
			printf("\n!!! TARGET ADDRESS MATCH DETECTED !!!\n");
			for (int i = 0; i < h_hit_count; ++i) {
				std::string hit_addr = "";
				std::string alt_addr = "";

				if (h_hits[i].type == 0) {
					hit_addr = base58check_encode(0x00, h_hits[i].hash160);
					alt_addr = bech32_encode(h_hits[i].hash160);
					printf("  MATCH TYPE: Compressed Derivation (P2PKH / Bech32)\n");
					printf("  PRIVATE KEY: "); print_hex_256(h_hits[i].private_key);
					printf("\n  P2PKH Address:  %s\n", hit_addr.c_str());
					printf("  Bech32 Address: %s\n\n", alt_addr.c_str());
				}
				else if (h_hits[i].type == 1) {
					hit_addr = base58check_encode(0x00, h_hits[i].hash160);
					printf("  MATCH TYPE: Uncompressed Derivation (P2PKH)\n");
					printf("  PRIVATE KEY: "); print_hex_256(h_hits[i].private_key);
					printf("\n  P2PKH Address:  %s\n\n", hit_addr.c_str());
				}
				else if (h_hits[i].type == 2) {
					hit_addr = base58check_encode(0x05, h_hits[i].hash160);
					printf("  MATCH TYPE: Nested SegWit Derivation (P2SH-P2WPKH)\n");
					printf("  PRIVATE KEY: "); print_hex_256(h_hits[i].private_key);
					printf("\n  P2SH Address:   %s\n\n", hit_addr.c_str());
				}

				// Save to found.txt (append only)
				std::ofstream out_file(found_path, std::ios::app);
				if (out_file.is_open()) {
					out_file << "Direct Target Hit | Match Type: " << (int)h_hits[i].type << "\n";
					out_file << "Private: ";
					for (int w = 7; w >= 0; w--) {
						out_file << std::hex << std::setw(8) << std::setfill('0') << std::uppercase << h_hits[i].private_key.v[w];
					}
					out_file << "\nAddress: " << hit_addr;
					if (!alt_addr.empty()) {
						out_file << " (Alternative Bech32: " << alt_addr << ")";
					}
					out_file << "\n\n";
					out_file.close();
				}
			}
			cudaMemset(d_hit_count, 0, sizeof(int));
		}

		// 2. Check Partial/Vanity Patterns
		if (!partial_patterns.empty()) {
			cudaMemcpy(h_all_hashes.data(), d_all_hashes, total_batch_size * sizeof(GPUResult), cudaMemcpyDeviceToHost);
			check_patterns_parallel(h_all_hashes, partial_patterns, base_key, found_path);
		}

		accumulated_keys += total_batch_size;
		auto current_time_loop = std::chrono::high_resolution_clock::now();
		std::chrono::duration<double> current_dur = current_time_loop - execution_start;
		if (current_dur.count() >= 5.0) {
			double rate = (double)accumulated_keys / current_dur.count();
			printf("[Active] Checked %llu keys | Speed: %.2f MKey/s\n", accumulated_keys, rate / 1000000.0);
			accumulated_keys = 0;
			execution_start = std::chrono::high_resolution_clock::now();
		}
	}
	

	// Cleanup resources and stop pregeneration thread
	stop_pregen_thread = true;
	queue_cv.notify_all();
	pregen_thread.join();

	if (d_targets) cudaFree(d_targets);
	if (d_all_hashes) cudaFree(d_all_hashes);
	cudaFree(d_hits);
	cudaFree(d_hit_count);
	return 0;
}
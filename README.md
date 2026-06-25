# VanitySearch

`VanitySearch` is a high-performance utility designed to generate private keys, derive corresponding elliptic curve public keys, and search for target matches against a database of addresses or partial patterns. The application features a dual-engine architecture: a massively parallel GPU-accelerated engine using CUDA, and a multi-threaded CPU-only fallback engine.

---

## Technical Features

* **Supported Address Formats:** 
  * P2PKH Compressed (Legacy starting with `1`)
  * P2PKH Uncompressed (Legacy starting with `1`)
  * P2SH / Nested SegWit (P2SH-P2WPKH starting with `3`)
  * Bech32 / Native SegWit (P2WPKH starting with `bc1q`)
* **GPU (CUDA) Core Optimization:**
  * Massive parallel secp256k1 point multiplication ($Q = dG$) using Jacobian coordinates to eliminate runtime division overhead.
  * Optimized 256-bit modular arithmetic with fast Solinas/Pseudo-Mersenne modular reduction .
  * Custom register sliding-window SHA-256 and unrolled register-direct RIPEMD-160 steps.
  * Hardware-accelerated endianness swapping utilizing native `__byte_perm` assembly intrinsics.
  * Fast $O(\log N)$ binary search matching executed directly inside the GPU device threads.
* **CPU Host & Fallback Engine:**
  * Multi-threaded host-side parallel pattern matcher utilizing the maximum available hardware logical threads (`std::thread::hardware_concurrency()`).
  * Lazy evaluation of address formatting (Base58Check and Bech32 are only executed when required by the matching pattern to minimize CPU serialization limits).
* **Tamper-Free Entropy Pipeline:**
  * Multi-source entropy mixer blending Microsoft CNG (`BCryptGenRandom`), direct Intel CPU Hardware Entropy (`RDRAND` via compile-time intrinsics with a fallback), high-resolution system clock ticks, and stack pointer address space jitter.
  * Crypotgraphically mixed using SHA-256 on the host.
  * Thread-safe background queue keeping up to 11 high-entropy base keys pre-generated and ready for rotation.
  * 33-second secure base key rotation to continuously explore different quadrants of the secp256k1 scalar field.

---

## Architectural Layout

The project separates execution responsibilities to optimize compilation stability and prevent platform-specific compiler conflicts:

### 1. GPU (CUDA) Generation Engine (`CudaBTCGen.h`)
This header holds all device-level mathematical, hashing, and serialization pipelines. Using `__device__ __forceinline__` decorators, the compiler compiles the mathematical routines directly into the GPU registers, maximizing occupancy and warp scheduling.

### 2. Host Search & Fallback Engine (`kernel.cu`)
This acts as the primary orchestrator. It manages the runtime file-I/O, performs the cryptographic verification testing on startup, handles interactive path prompt loops, handles multi-threaded host pattern checks, and drives the CUDA search kernel launches.

---

## The Dual-Engine Implementations

### A. GPU-Accelerated (CUDA) Version
The GPU version utilizes a block grid containing **4,096 blocks** and **256 threads per block**, processing exactly **1,048,576 private keys in parallel** per batch launch. 

* **Direct Match (Exact Targets):** 
  Complete legacy, SegWit, or Bech32 addresses loaded from the database file are decoded into raw 20-byte `HASH160` target structures on startup. The sorted target array is copied to the GPU's global memory. The device threads perform high-speed binary searches on every generated hash, which executes without impacting key generation throughput.
* **Prefix / Suffix Matches (Partial Patterns):** 
  If partial vanity patterns (like `1Love` or `3Love`) are specified, the GPU copies the entire block of generated HASH160 bytes back to host memory (which takes ~3–5 ms over PCIe). The multi-threaded CPU host then evaluates these hashes in parallel.

### B. CPU-Only Fallback Version
Also included in the repository is a CPU-only implementation. This is useful for systems without an active CUDA-capable graphics processor, virtual machines, or testing environments.
* The CPU version executes the same secp256k1 point multiplication, hashing, and formatting, but organizes the workload using a thread pool mapped to the logical processor cores of your CPU.
* It leverages standard CPU vector instructions (SIMD) and standard multi-threading libraries to partition and search the key space sequentially.

---

## Verification & Self-Testing

To ensure the execution stack remains mathematically sound across different hardware configurations, `VanitySearch` performs a **Three-Phase Self-Test** on startup before beginning any lookup loops:

1. **Stack Integrity Check:** Evaluates 55 hardcoded test vectors (private keys with known legacy compressed, uncompressed, SegWit, and Bech32 addresses). It compares the GPU's outputs directly against these known specifications. If even a single carry-bit, point-addition, or hashing byte is miscalculated, the stack is flagged and execution halts.
2. **Live Sampling Check:** Generates and prints 20 random private keys and address formats using the tamper-free entropy engine, allowing you to manually verify outputs in offline address-checking tools.
3. **Database Setup:** Loads search targets, validates Base58Check checksums, and filters out mathematically impossible Bech32 patterns (such as patterns containing standard restricted Bech32 characters like `b`, `o`, `i`, or `1` which BIP 173 excludes).

---

## Build Prerequisites

* **Operating System:** Windows 10/11 (64-bit)
* **Compiler:** Visual Studio 2026 Enterprise (MSBuild MSVC v145 toolchain)
* **CUDA SDK:** NVIDIA CUDA Toolkit v13.3 (or later compatible)
* **GPU Target:** NVIDIA RTX Series GPU (Compiled natively for Compute Capability `sm_120` or your hardware architecture)

---

## Compilation

1. Open your project solution (`.sln`) inside **Visual Studio 2026**.
2. Set the build configuration to **Release / x64**.
3. Right-click on your Project $\rightarrow$ **Properties**:
   * Under **CUDA C/C++** $\rightarrow$ **Device** $\rightarrow$ **Code Generation**: Ensure it is set to `compute_120,sm_120` (or matching your hardware's compute capability).
   * Under **CUDA C/C++** $\rightarrow$ **Common** $\rightarrow$ **Optimization**: Set to `O3 (Maximize Speed)`.
   * Under **CUDA C/C++** $\rightarrow$ **Common** $\rightarrow$ **Use Fast Math**: Set to `Yes (-use_fast_math)`.
4. Right-click on your solution and select **Rebuild**.

---

## Usage

On execution, the program will look for `database.txt` in its local execution directory. 
* If it is not found, you will be prompted to either enter a custom path to your database or run the application in **Benchmark-only mode**.
* If a database is loaded, you can choose where to output your matches (e.g. `found.txt`). Leaving this blank will save the matches inside `found.txt` directly next to your database file.

All matches (direct targets and partial patterns) are saved into the specified output file in append-only mode.
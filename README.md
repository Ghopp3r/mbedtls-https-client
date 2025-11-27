# mbedtls-https-client

Small standalone HTTPS client built on mbedTLS with certificate verification, optional pinning, and custom timeouts. No libcurl dependency.

## Features
- HTTPS over mbedTLS with system CA verification.
- Optional certificate pinning (serial, SHA-256 fingerprint, subject).
- Per-request timeouts and non-blocking connect with select-based timeout.
- Chunked transfer decoding and basic HTTP/1.1 response parsing.
- Minimal logging toggle via `ENABLE_VERBOSE_LOGGING`.

## Build
Requirements: CMake ≥ 3.15, a C++17 toolchain, and mbedTLS static libs + headers placed under `third_party/mbedtls/{include,lib}` (already present in this tree).

Linux/macOS (host build):
```bash
cmake -S . -B build -G Ninja -DENABLE_VERBOSE_LOGGING=ON
cmake --build build --config Release
```
The binary `curl_alt` will be under `build/`.

Android cross-build (NDK):
```bash
cmake -S . -B build-arm64 -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=/path/to/android-ndk/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=arm64-v8a \
  -DANDROID_PLATFORM=android-21
cmake --build build-arm64 --config Release
```
Make sure `third_party/mbedtls/lib/*.a` matches your target ABI; replace them if needed.

## Usage
See `src/Main.cpp` for a minimal GET request:
```cpp
HttpsClient client(10);
// client.addPinnedCertificate("example.com", "00:11:22:33:44:55", "AABB...", "CN=Example");
HttpsRequest req("https://example.com", "GET", 10);
HttpsResponse res = client.performRequest(req);
```
Run the built binary; it prints status, TLS verification result, pinning status, and body preview.

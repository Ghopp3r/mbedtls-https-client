#include <iostream>

#include "HttpsClient.h"

int main() {
    HttpsClient client(10);

    // Optional: enable pinning if you know the exact certificate details.
    // client.addPinnedCertificate(
    //     "example.com",
    //     "00:11:22:33:44:55", // serial (hex with colons)
    //     "AABBCCDDEEFF...", // SHA-256 fingerprint (hex)
    //     "CN=Example" // subject (optional match)
    // );

    HttpsRequest request("https://example.com", "GET", 10);
    request.headers["Accept"] = "application/json";

    HttpsResponse response = client.performRequest(request);
    if (!response.error_message.empty()) {
        std::cerr << "Request failed: " << response.error_message << std::endl;
        return 1;
    }

    std::cout << "Status: " << response.status_code << std::endl;
    std::cout << "Verified TLS: " << (response.ssl_verification_passed ? "yes" : "no") << std::endl;
    if (response.pinning_configured) {
        std::cout << "Pinning: " << (response.certificate_pinning_passed ? "pass" : "fail") << std::endl;
    } else {
        std::cout << "Pinning: skip (not configured)" << std::endl;
    }

    std::cout << "---- Response body (truncated) ----" << std::endl;
    if (response.body.size() > 800) {
        std::cout << response.body.substr(0, 800) << "\n[truncated]" << std::endl;
    } else {
        std::cout << response.body << std::endl;
    }

    return 0;
}

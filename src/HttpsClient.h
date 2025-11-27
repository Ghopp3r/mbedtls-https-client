#ifndef CLEARPROJECT_HTTPS_CLIENT_H
#define CLEARPROJECT_HTTPS_CLIENT_H

#include <arpa/inet.h>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <map>
#include <netdb.h>
#include <string>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <vector>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/md.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_internal.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"

#ifndef LOGI
#ifdef ENABLE_VERBOSE_LOGGING
#include <cstdio>
#define LOGI(fmt, ...) fprintf(stdout, "[I] " fmt "\n", ##__VA_ARGS__)
#define LOGD(fmt, ...) fprintf(stdout, "[D] " fmt "\n", ##__VA_ARGS__)
#define LOGW(fmt, ...) fprintf(stderr, "[W] " fmt "\n", ##__VA_ARGS__)
#define LOGE(fmt, ...) fprintf(stderr, "[E] " fmt "\n", ##__VA_ARGS__)
#else
#define LOGI(fmt, ...) (void)0
#define LOGD(fmt, ...) (void)0
#define LOGW(fmt, ...) (void)0
#define LOGE(fmt, ...) (void)0
#endif
#endif

struct CertificateInfo {
    std::string serial_number;
    std::string fingerprint_sha256;
    std::string subject;
    std::string issuer;
    std::string valid_from;
    std::string valid_to;
    std::string public_key_type;
    size_t public_key_size = 0;
    bool is_valid = false;
    bool is_expired = false;
    bool is_future = false;
};

struct HttpsRequest {
    std::string url;
    std::string method;
    std::string host;
    std::string path;
    int port = 443;
    std::map<std::string, std::string> headers;
    std::string body;
    int timeout_seconds = 10;

    HttpsRequest(const std::string& url_in, const std::string& method_in, int timeout = 10) : url(url_in), method(method_in), timeout_seconds(timeout) {
        parseUrl();
    }

    void parseUrl();
    std::string buildRequest() const;
};

struct HttpsResponse {
    int status_code = 0;
    std::map<std::string, std::string> headers;
    std::string body;
    std::string error_message;

    bool ssl_verification_passed = false;
    bool certificate_pinning_passed = false;
    bool pinning_configured = false;

    CertificateInfo certificate;
    CertificateInfo pinned_certificate;

    bool isSecure() const {
        bool pin_ok = !pinning_configured || certificate_pinning_passed;
        return ssl_verification_passed && pin_ok && status_code > 0;
    }
};

class HttpsClient {
public:
    explicit HttpsClient(int timeout_seconds = 10);
    HttpsClient(HttpsClient&& other) noexcept;
    HttpsClient& operator=(HttpsClient&& other) noexcept;
    HttpsClient(const HttpsClient&) = delete;
    HttpsClient& operator=(const HttpsClient&) = delete;
    ~HttpsClient();

    void setTimeout(int timeout_seconds);
    int getTimeout() const;
    bool initialize();
    void addPinnedCertificate(const std::string& hostname, const std::string& expected_serial, const std::string& expected_fingerprint, const std::string& expected_subject = "");
    HttpsResponse performRequest(const HttpsRequest& request);

private:
    struct RequestTimer {
        time_t start_time;
        time_t connection_time;
        time_t handshake_time;
        time_t send_time;
        time_t receive_time;
        time_t total_time;
        int timeout_seconds;

        explicit RequestTimer(int timeout = 10);
        void reset();
        void markConnection();
        void markHandshake();
        void markSend();
        void markReceive();
        void finish();

        int getConnectionDuration() const;
        int getHandshakeDuration() const;
        int getSendDuration() const;
        int getReceiveDuration() const;
        int getTotalDuration() const;
        bool isTimeout() const;
        int getRemainingTime() const;
    };

    struct RequestResources {
        mbedtls_net_context server_fd;
        mbedtls_ssl_context ssl;
        mbedtls_ssl_config conf;
        int sockfd;

        RequestResources();
        ~RequestResources();
        void cleanup();
        void closeSocket(int fd);
    };

    CertificateInfo extractCertificateInfo(const mbedtls_x509_crt* cert);
    bool verifyCertificatePinning(const mbedtls_x509_crt* cert, const std::string& hostname);
    void getCertificateSerialHex(const mbedtls_x509_crt* cert, char* buffer, size_t buffer_size);
    int getCertificateFingerprintSha256(const mbedtls_x509_crt* cert, unsigned char* fingerprint);
    void parseHttpsResponse(const std::string& raw_response, HttpsResponse& response);
    void processChunkedBody(std::string& body);
    void cleanup();
    bool isTimeoutReached(time_t start_time, int timeout_seconds);
    int connectWithTimeout(const std::string& host, int port, int timeout_seconds);
    void closeSocket(int sockfd);

    mbedtls_net_context server_fd_;
    mbedtls_ssl_context ssl_;
    mbedtls_ssl_config conf_;
    mbedtls_x509_crt cacert_;
    mbedtls_ctr_drbg_context ctr_drbg_;
    mbedtls_entropy_context entropy_;

    std::map<std::string, CertificateInfo> pinned_certificates_;
    int default_timeout_seconds_;
    bool initialized_;
};

#endif  // CLEARPROJECT_HTTPS_CLIENT_H

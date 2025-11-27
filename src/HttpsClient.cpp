#include "HttpsClient.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <sstream>

using std::string;

namespace {
    bool load_system_ca(mbedtls_x509_crt* cacert) {
        const char* ca_paths[] = {
            "/etc/ssl/certs", // common on Linux
            "/system/etc/security/cacerts", // Android
            "/system/etc/ssl/certs" // Android alt path
        };

        for (const char* path : ca_paths) {
            int ret = mbedtls_x509_crt_parse_path(cacert, path);
            if (ret >= 0) {
                LOGI("Loaded CA bundle from %s", path);
                return true;
            }
            LOGW("Failed to load CA bundle from %s (ret=%d)", path, ret);
        }
        return false;
    }
}  // namespace

void HttpsRequest::parseUrl() {
    LOGD("parseUrl called for %s", url.c_str());

    if (url.rfind("https://", 0) != 0) {
        LOGW("Only https:// URLs are supported");
        return;
    }

    string without_scheme = url.substr(8);
    size_t slash_pos = without_scheme.find('/');
    if (slash_pos != string::npos) {
        host = without_scheme.substr(0, slash_pos);
        path = without_scheme.substr(slash_pos);
    } else {
        host = without_scheme;
        path = "/";
    }

    size_t colon_pos = host.find(':');
    if (colon_pos != string::npos) {
        string port_str = host.substr(colon_pos + 1);
        port = std::atoi(port_str.c_str());
        host = host.substr(0, colon_pos);
    }

    LOGI("Parsed host=%s port=%d path=%s", host.c_str(), port, path.c_str());
}

string HttpsRequest::buildRequest() const {
    string request = method + " " + path + " HTTP/1.1\r\n";
    request += "Host: " + host;
    if (port != 443) {
        request += ":" + std::to_string(port);
    }
    request += "\r\n";
    request += "User-Agent: ClearCurlAlt/1.0\r\n";
    request += "Accept: */*\r\n";
    request += "Connection: close\r\n";

    for (const auto& header : headers) {
        request += header.first + ": " + header.second + "\r\n";
    }

    if (!body.empty()) {
        request += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    }

    request += "\r\n";
    request += body;
    LOGD("buildRequest len=%zu", request.size());
    return request;
}

HttpsClient::RequestTimer::RequestTimer(int timeout) : timeout_seconds(timeout) {
    reset();
}

void HttpsClient::RequestTimer::reset() {
    start_time = time(nullptr);
    connection_time = 0;
    handshake_time = 0;
    send_time = 0;
    receive_time = 0;
    total_time = 0;
}

void HttpsClient::RequestTimer::markConnection() { connection_time = time(nullptr); }
void HttpsClient::RequestTimer::markHandshake() { handshake_time = time(nullptr); }
void HttpsClient::RequestTimer::markSend() { send_time = time(nullptr); }
void HttpsClient::RequestTimer::markReceive() { receive_time = time(nullptr); }
void HttpsClient::RequestTimer::finish() { total_time = time(nullptr); }

int HttpsClient::RequestTimer::getConnectionDuration() const { return connection_time - start_time; }
int HttpsClient::RequestTimer::getHandshakeDuration() const { return handshake_time - connection_time; }
int HttpsClient::RequestTimer::getSendDuration() const { return send_time - handshake_time; }
int HttpsClient::RequestTimer::getReceiveDuration() const { return receive_time - send_time; }
int HttpsClient::RequestTimer::getTotalDuration() const { return total_time - start_time; }

bool HttpsClient::RequestTimer::isTimeout() const {
    return (time(nullptr) - start_time) >= timeout_seconds;
}

int HttpsClient::RequestTimer::getRemainingTime() const {
    int elapsed = static_cast<int>(time(nullptr) - start_time);
    return std::max(0, timeout_seconds - elapsed);
}

HttpsClient::RequestResources::RequestResources() : sockfd(-1) {
    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
}

HttpsClient::RequestResources::~RequestResources() {
    cleanup();
}

void HttpsClient::RequestResources::cleanup() {
    if (ssl.state != MBEDTLS_SSL_HELLO_REQUEST) {
        mbedtls_ssl_close_notify(&ssl);
    }
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);

    if (sockfd >= 0) {
        closeSocket(sockfd);
        sockfd = -1;
    }

    mbedtls_net_init(&server_fd);
}

void HttpsClient::RequestResources::closeSocket(int fd) {
    ::close(fd);
}

HttpsClient::HttpsClient(int timeout_seconds) : default_timeout_seconds_(timeout_seconds), initialized_(false) {
    mbedtls_net_init(&server_fd_);
    mbedtls_ssl_init(&ssl_);
    mbedtls_ssl_config_init(&conf_);
    mbedtls_x509_crt_init(&cacert_);
    mbedtls_ctr_drbg_init(&ctr_drbg_);
    mbedtls_entropy_init(&entropy_);
}

HttpsClient::HttpsClient(HttpsClient&& other) noexcept : pinned_certificates_(std::move(other.pinned_certificates_)), default_timeout_seconds_(other.default_timeout_seconds_), initialized_(other.initialized_) {
    server_fd_ = other.server_fd_;
    ssl_ = other.ssl_;
    conf_ = other.conf_;
    cacert_ = other.cacert_;
    ctr_drbg_ = other.ctr_drbg_;
    entropy_ = other.entropy_;

    other.initialized_ = false;
    mbedtls_net_init(&other.server_fd_);
    mbedtls_ssl_init(&other.ssl_);
    mbedtls_ssl_config_init(&other.conf_);
    mbedtls_x509_crt_init(&other.cacert_);
    mbedtls_ctr_drbg_init(&other.ctr_drbg_);
    mbedtls_entropy_init(&other.entropy_);
}

HttpsClient& HttpsClient::operator=(HttpsClient&& other) noexcept {
    if (this != &other) {
        cleanup();
        pinned_certificates_ = std::move(other.pinned_certificates_);
        default_timeout_seconds_ = other.default_timeout_seconds_;
        initialized_ = other.initialized_;

        server_fd_ = other.server_fd_;
        ssl_ = other.ssl_;
        conf_ = other.conf_;
        cacert_ = other.cacert_;
        ctr_drbg_ = other.ctr_drbg_;
        entropy_ = other.entropy_;

        other.initialized_ = false;
        mbedtls_net_init(&other.server_fd_);
        mbedtls_ssl_init(&other.ssl_);
        mbedtls_ssl_config_init(&other.conf_);
        mbedtls_x509_crt_init(&other.cacert_);
        mbedtls_ctr_drbg_init(&other.ctr_drbg_);
        mbedtls_entropy_init(&other.entropy_);
    }
    return *this;
}

HttpsClient::~HttpsClient() {
    cleanup();
}

void HttpsClient::setTimeout(int timeout_seconds) {
    default_timeout_seconds_ = timeout_seconds;
}

int HttpsClient::getTimeout() const {
    return default_timeout_seconds_;
}

bool HttpsClient::initialize() {
    if (initialized_) {
        return true;
    }

    const char* pers = "https_client";
    mbedtls_ctr_drbg_init(&ctr_drbg_);
    mbedtls_entropy_init(&entropy_);
    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg_, mbedtls_entropy_func, &entropy_, reinterpret_cast<const unsigned char*>(pers), strlen(pers));
    if (ret != 0) {
        LOGE("Failed to seed RNG: %d", ret);
        return false;
    }

    mbedtls_x509_crt_init(&cacert_);
    if (!load_system_ca(&cacert_)) {
        LOGW("No system CA bundle loaded; TLS verification may fail.");
    }

    initialized_ = true;
    return true;
}

void HttpsClient::addPinnedCertificate(const std::string& hostname, const std::string& expected_serial, const std::string& expected_fingerprint, const std::string& expected_subject) {
    CertificateInfo info;
    info.serial_number = expected_serial;
    info.fingerprint_sha256 = expected_fingerprint;
    info.subject = expected_subject;
    pinned_certificates_[hostname] = info;
}

CertificateInfo HttpsClient::extractCertificateInfo(const mbedtls_x509_crt* cert) {
    CertificateInfo info;
    if (!cert) {
        return info;
    }

    char serial_hex[256] = {0};
    getCertificateSerialHex(cert, serial_hex, sizeof(serial_hex));
    info.serial_number = serial_hex;

    unsigned char fingerprint[32];
    if (getCertificateFingerprintSha256(cert, fingerprint) == 0) {
        char fingerprint_hex[65] = {0};
        for (int i = 0; i < 32; i++) {
            std::snprintf(fingerprint_hex + i * 2, 3, "%02X", fingerprint[i]);
        }
        info.fingerprint_sha256 = fingerprint_hex;
    }

    char subject[512];
    mbedtls_x509_dn_gets(subject, sizeof(subject), &cert->subject);
    info.subject = subject;

    char issuer[512];
    mbedtls_x509_dn_gets(issuer, sizeof(issuer), &cert->issuer);
    info.issuer = issuer;

    char time_buf[32];
    std::snprintf(time_buf, sizeof(time_buf), "%04d-%02d-%02d %02d:%02d:%02d", cert->valid_from.year, cert->valid_from.mon, cert->valid_from.day, cert->valid_from.hour, cert->valid_from.min, cert->valid_from.sec);
    info.valid_from = time_buf;

    std::snprintf(time_buf, sizeof(time_buf), "%04d-%02d-%02d %02d:%02d:%02d", cert->valid_to.year, cert->valid_to.mon, cert->valid_to.day, cert->valid_to.hour, cert->valid_to.min, cert->valid_to.sec);
    info.valid_to = time_buf;

    info.public_key_type = mbedtls_pk_get_name(&cert->pk);
    info.public_key_size = mbedtls_pk_get_bitlen(&cert->pk);

    info.is_expired = mbedtls_x509_time_is_past(&cert->valid_to);
    info.is_future = mbedtls_x509_time_is_future(&cert->valid_from);
    info.is_valid = !info.is_expired && !info.is_future;

    return info;
}

bool HttpsClient::verifyCertificatePinning(const mbedtls_x509_crt* cert, const std::string& hostname) {
    auto it = pinned_certificates_.find(hostname);
    if (it == pinned_certificates_.end()) {
        return true;
    }

    const CertificateInfo& pinned = it->second;
    CertificateInfo current = extractCertificateInfo(cert);

    bool serial_match = pinned.serial_number.empty() || pinned.serial_number == current.serial_number;
    bool fingerprint_match = pinned.fingerprint_sha256.empty() || pinned.fingerprint_sha256 == current.fingerprint_sha256;
    bool subject_match = pinned.subject.empty() || pinned.subject == current.subject;

    return serial_match && fingerprint_match && subject_match;
}

void HttpsClient::getCertificateSerialHex(const mbedtls_x509_crt* cert, char* buffer, size_t buffer_size) {
    size_t pos = 0;
    for (size_t i = 0; i < cert->serial.len && pos + 3 < buffer_size; i++) {
        pos += std::snprintf(buffer + pos, buffer_size - pos, "%02X", cert->serial.p[i]);
        if (i + 1 < cert->serial.len && pos + 2 < buffer_size) {
            pos += std::snprintf(buffer + pos, buffer_size - pos, ":");
        }
    }
}

int HttpsClient::getCertificateFingerprintSha256(const mbedtls_x509_crt* cert, unsigned char* fingerprint) {
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md_info == nullptr) {
        return -1;
    }
    return mbedtls_md(md_info, cert->raw.p, cert->raw.len, fingerprint);
}

void HttpsClient::parseHttpsResponse(const string& raw_response, HttpsResponse& response) {
    if (raw_response.empty()) {
        response.error_message = "Empty response";
        return;
    }

    size_t header_end = raw_response.find("\r\n\r\n");
    if (header_end == string::npos) {
        header_end = raw_response.find("\n\n");
    }
    if (header_end == string::npos) {
        response.error_message = "Invalid HTTP response";
        return;
    }

    string headers = raw_response.substr(0, header_end);
    if (header_end + 4 <= raw_response.size()) {
        response.body = raw_response.substr(header_end + 4);
    }

    size_t first_line_end = headers.find('\n');
    if (first_line_end != string::npos) {
        string status_line = headers.substr(0, first_line_end);
        if (!status_line.empty() && status_line.back() == '\r') {
            status_line.pop_back();
        }
        size_t space1 = status_line.find(' ');
        if (space1 != string::npos) {
            size_t space2 = status_line.find(' ', space1 + 1);
            string status_code_str = (space2 != string::npos) ? status_line.substr(space1 + 1, space2 - space1 - 1) : status_line.substr(space1 + 1);
            response.status_code = std::atoi(status_code_str.c_str());
        }
    }

    size_t pos = first_line_end == string::npos ? headers.size() : first_line_end + 1;
    string key, value;
    while (pos < headers.size()) {
        size_t line_end = headers.find('\n', pos);
        if (line_end == string::npos) {
            line_end = headers.size();
        }
        string line = headers.substr(pos, line_end - pos);
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (!line.empty()) {
            size_t colon = line.find(':');
            if (colon != string::npos) {
                key = line.substr(0, colon);
                value = line.substr(colon + 1);
                if (!value.empty() && value.front() == ' ') {
                    value.erase(value.begin());
                }
                response.headers[key] = value;
            }
        }
        pos = line_end + 1;
    }

    auto te = response.headers.find("Transfer-Encoding");
    if (te != response.headers.end() && te->second.find("chunked") != string::npos) {
        processChunkedBody(response.body);
    }
}

void HttpsClient::processChunkedBody(string& body) {
    string output;
    size_t pos = 0;
    while (pos < body.size()) {
        size_t endline = body.find('\n', pos);
        if (endline == string::npos) {
            break;
        }
        string size_line = body.substr(pos, endline - pos);
        if (!size_line.empty() && size_line.back() == '\r') {
            size_line.pop_back();
        }
        size_t semicolon = size_line.find(';');
        if (semicolon != string::npos) {
            size_line = size_line.substr(0, semicolon);
        }

        size_t chunk_size = 0;
        try {
            chunk_size = std::stoul(size_line, nullptr, 16);
        } catch (...) {
            break;
        }

        pos = endline + 1;
        if (chunk_size == 0) {
            break;
        }
        if (pos + chunk_size > body.size()) {
            break;
        }

        output.append(body, pos, chunk_size);
        pos += chunk_size + 2; // skip \r\n after chunk
    }
    body.swap(output);
}

void HttpsClient::cleanup() {
    if (initialized_) {
        mbedtls_net_free(&server_fd_);
        mbedtls_ssl_free(&ssl_);
        mbedtls_ssl_config_free(&conf_);
        mbedtls_x509_crt_free(&cacert_);
        mbedtls_ctr_drbg_free(&ctr_drbg_);
        mbedtls_entropy_free(&entropy_);
        initialized_ = false;
    }
}

bool HttpsClient::isTimeoutReached(time_t start_time, int timeout_seconds) {
    return (time(nullptr) - start_time) >= timeout_seconds;
}

int HttpsClient::connectWithTimeout(const string& host, int port, int timeout_seconds) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* result = nullptr;
    string port_str = std::to_string(port);
    int gai_ret = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &result);
    if (gai_ret != 0) {
        LOGE("getaddrinfo failed: %s", gai_strerror(gai_ret));
        return -1;
    }

    int sockfd = -1;
    for (addrinfo* rp = result; rp != nullptr; rp = rp->ai_next) {
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd < 0) {
            continue;
        }

        int flags = fcntl(sockfd, F_GETFL, 0);
        fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

        int ret = connect(sockfd, rp->ai_addr, rp->ai_addrlen);
        if (ret == 0) {
            fcntl(sockfd, F_SETFL, flags);
            break;
        }
        if (ret < 0 && errno == EINPROGRESS) {
            fd_set wfds, efds;
            FD_ZERO(&wfds);
            FD_ZERO(&efds);
            FD_SET(sockfd, &wfds);
            FD_SET(sockfd, &efds);

            timeval tv{};
            tv.tv_sec = timeout_seconds;
            tv.tv_usec = 0;
            ret = select(sockfd + 1, nullptr, &wfds, &efds, &tv);
            if (ret > 0 && FD_ISSET(sockfd, &wfds) && !FD_ISSET(sockfd, &efds)) {
                fcntl(sockfd, F_SETFL, flags);
                break;
            }
        }

        close(sockfd);
        sockfd = -1;
    }

    freeaddrinfo(result);
    if (sockfd < 0) {
        LOGE("Connection to %s:%d failed", host.c_str(), port);
    }
    return sockfd;
}

void HttpsClient::closeSocket(int sockfd) {
    ::close(sockfd);
}

HttpsResponse HttpsClient::performRequest(const HttpsRequest& request) {
    HttpsResponse response;
    int timeout_seconds = request.timeout_seconds > 0 ? request.timeout_seconds : default_timeout_seconds_;
    RequestTimer timer(timeout_seconds);
    RequestResources resources;

    if (request.url.rfind("https://", 0) != 0) {
        response.error_message = "Only HTTPS URLs are allowed";
        return response;
    }

    if (!initialized_ && !initialize()) {
        response.error_message = "Failed to initialize requests";
        return response;
    }

    resources.sockfd = connectWithTimeout(request.host, request.port, timeout_seconds);
    if (resources.sockfd < 0) {
        response.error_message = "TCP connection failed";
        return response;
    }
    resources.server_fd.fd = resources.sockfd;
    timer.markConnection();

    int ret = mbedtls_ssl_config_defaults(&resources.conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        char buf[256];
        mbedtls_strerror(ret, buf, sizeof(buf));
        response.error_message = string("SSL config failed: ") + buf;
        return response;
    }

    mbedtls_ssl_conf_authmode(&resources.conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&resources.conf, &cacert_, nullptr);
    mbedtls_ssl_conf_rng(&resources.conf, mbedtls_ctr_drbg_random, &ctr_drbg_);
    mbedtls_ssl_conf_read_timeout(&resources.conf, static_cast<uint32_t>(timeout_seconds * 1000));
    mbedtls_ssl_conf_min_version(&resources.conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);

    ret = mbedtls_ssl_setup(&resources.ssl, &resources.conf);
    if (ret != 0) {
        char buf[256];
        mbedtls_strerror(ret, buf, sizeof(buf));
        response.error_message = string("SSL setup failed: ") + buf;
        return response;
    }

    mbedtls_ssl_set_hostname(&resources.ssl, request.host.c_str());
    mbedtls_ssl_set_bio(&resources.ssl, &resources.server_fd, mbedtls_net_send, nullptr, mbedtls_net_recv_timeout);

    do {
        ret = mbedtls_ssl_handshake(&resources.ssl);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            if (timer.isTimeout()) {
                response.error_message = "TLS handshake timeout";
                return response;
            }
            continue;
        }
        break;
    } while (true);

    timer.markHandshake();
    if (ret != 0) {
        char buf[256];
        mbedtls_strerror(ret, buf, sizeof(buf));
        response.error_message = string("TLS handshake failed: ") + buf;
        return response;
    }

    uint32_t flags = mbedtls_ssl_get_verify_result(&resources.ssl);
    response.ssl_verification_passed = (flags == 0);
    const mbedtls_x509_crt* peer_cert = mbedtls_ssl_get_peer_cert(&resources.ssl);
    response.certificate = extractCertificateInfo(peer_cert);
    auto pinned_it = pinned_certificates_.find(request.host);
    bool has_pin = pinned_it != pinned_certificates_.end();
    response.pinning_configured = has_pin;
    if (has_pin) {
        response.pinned_certificate = pinned_it->second;
        response.certificate_pinning_passed = verifyCertificatePinning(peer_cert, request.host);
        if (!response.certificate_pinning_passed) {
            response.error_message = "Certificate pinning failed";
            return response;
        }
    }

    string payload = request.buildRequest();
    const unsigned char* data = reinterpret_cast<const unsigned char*>(payload.data());
    size_t to_write = payload.size();
    while (to_write > 0) {
        ret = mbedtls_ssl_write(&resources.ssl, data, to_write);
        if (ret > 0) {
            to_write -= static_cast<size_t>(ret);
            data += ret;
            continue;
        }
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            if (timer.isTimeout()) {
                response.error_message = "Send timeout";
                return response;
            }
            continue;
        }
        char buf[256];
        mbedtls_strerror(ret, buf, sizeof(buf));
        response.error_message = string("Send failed: ") + buf;
        return response;
    }
    timer.markSend();

    string full_response;
    char read_buf[4096];
    while (!timer.isTimeout()) {
        ret = mbedtls_ssl_read(&resources.ssl, reinterpret_cast<unsigned char*>(read_buf), sizeof(read_buf) - 1);
        if (ret > 0) {
            full_response.append(read_buf, ret);
            continue;
        }
        if (ret == 0 || ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            break;
        }
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }
        char buf[256];
        mbedtls_strerror(ret, buf, sizeof(buf));
        response.error_message = string("Read failed: ") + buf;
        return response;
    }
    timer.markReceive();
    timer.finish();

    if (full_response.empty()) {
        response.error_message = "No response received";
        return response;
    }

    parseHttpsResponse(full_response, response);
    return response;
}

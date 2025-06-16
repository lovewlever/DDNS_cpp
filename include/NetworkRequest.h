//
// Created by catog on 2025/6/11.
//

#ifndef NETWORKREQUEST_H
#define NETWORKREQUEST_H
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"
#include <iostream>

class NetworkRequest {
private:
    NetworkRequest() = default;

    static const std::regex ipv4Regex;
    // Only verify whether ipv6 is legal
    static const std::regex ipv6Regex;
    // Extract ipv6 from string
    static const std::regex ipv6RegexTq;

    std::unique_ptr<httplib::SSLClient> getClient(const std::string &url) const;

public:
    ~NetworkRequest() = default;
    NetworkRequest(const NetworkRequest &) = delete;
    NetworkRequest &operator=(const NetworkRequest &) = delete;
    static NetworkRequest& getInstance();

    std::string getNetworkIpv4(const std::string& url) const;
    std::string getNetworkIpv6(const std::string& url) const;



};



#endif //NETWORKREQUEST_H

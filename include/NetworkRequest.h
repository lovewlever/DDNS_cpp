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

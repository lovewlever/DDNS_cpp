//
// Created by catog on 2025/6/11.
//

#ifndef GETTHELOCALIP_H
#define GETTHELOCALIP_H
#include <winsock2.h>
#include <iphlpapi.h>
#include <string>

class GetTheLocalIP
{
public:
    GetTheLocalIP();

    ~GetTheLocalIP();

    std::string getLocalIp6();

private:
    struct Ipv6XX
    {
        std::string type;
        std::string ip;
    } typedef IPV6XX;
};


#endif //GETTHELOCALIP_H

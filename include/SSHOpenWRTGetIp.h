//
// Created by catog on 2025/6/11.
//

#ifndef SSHOPENWRTGETIP_H
#define SSHOPENWRTGETIP_H
#include <iostream>
#include <libssh2.h>
#include <winsock2.h>

/**
 * host,
 * user,
 * password,
 * port = 22,
 * command
 * interfaceName
 */
class SSHOpenWRTGetIp
{
private:
     const std::string host;
     const std::string user;
     const std::string password;
     const int32_t port = 22;
     const std::string interfaceName;
     const std::string command;

    WSADATA wsaData{};

    addrinfo hints = {}, *res{nullptr};
    void* addr{nullptr};

    libssh2_socket_t sock;

    sockaddr_in sin{};

    LIBSSH2_SESSION * session{nullptr};
    LIBSSH2_CHANNEL *channel{nullptr};

public:
    SSHOpenWRTGetIp(const std::string &host,
                    const std::string &user,
                    const std::string &password,
                    const int32_t port = 22,
                    const std::string &interfaceName = "pppoe-wan",
                    const std::string &command = "ip addr");

    ~SSHOpenWRTGetIp() = default;

    std::tuple<int32_t, std::string, std::string, std::string> execRemoteCommand();

private:
    std::tuple<int32_t, std::string, std::string, std::string> getRemoteIpv46();

    std::tuple<int32_t, std::string, std::string, std::string> readRemoteIpv46();

    std::tuple<int32_t, std::string> getIpv4(const std::string &cmdResult) const;
    std::tuple<int32_t, std::string> getIpv6(const std::string &cmdResult) const;

    void close();
};


#endif //SSHOPENWRTGETIP_H

//
// Created by catog on 2025/6/11.
//

#include "SSHOpenWRTGetIp.h"

#include "libssh2.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include "GLog.h"

SSHOpenWRTGetIp::SSHOpenWRTGetIp(const std::string &host,
                                 const std::string &user,
                                 const std::string &password,
                                 const int32_t port,
                                 const std::string &interfaceName,
                                 const std::string &command): host{host}, user{user}, password{password}, port{port},
                                                              interfaceName{interfaceName},
                                                              command{command}
{
}

/**
 *
 * @return tuple[code, msg, ipv4, ipv6]
 * code 0: ALL, 1:ipv4, 2:ipv6
 */
std::tuple<int32_t, std::string, std::string, std::string>
SSHOpenWRTGetIp::execRemoteCommand()
{
    const auto [code , msg, ipv4, ipv6] = this->getRemoteIpv46();
    const auto type = code == 0 ? "IPV4&IPv6" : code == 1 ? "IPv4 Only" : code == 2 ? "IPv6 Only" : "Unknown";
    GLog::log() << "Get IP from SSHOpenWRT: " << type << "; MSG: " << msg << "; IPv4: " << ipv4 << "; IPv6: " << ipv6 <<
            std::endl;
    this->close();
    return std::make_tuple(code, msg, ipv4, ipv6);
}

std::tuple<int32_t, std::string, std::string, std::string>
SSHOpenWRTGetIp::getRemoteIpv46()
{
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    if (libssh2_init(0) != 0)
    {
        GLog::log(GLog::LogLevelError) << "libssh2_init failed" << std::endl;
        this->close();
        return std::make_tuple(-1, "libssh2_init failed", "", "");
    }

    hints.ai_family = AF_UNSPEC; // 支持 IPv4 和 IPv6
    hints.ai_socktype = SOCK_STREAM;
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (const int err = getaddrinfo(host.c_str(), nullptr, &hints, &res); err != 0)
    {
        GLog::log(GLog::LogLevelError) << "getaddrinfo failed: " << gai_strerrorA(err) << std::endl;
        this->close();
        return std::make_tuple(-1, ("getaddrinfo failed: " + std::string{gai_strerrorA(err)}), "", "");
    }

    for (auto p = res; p != nullptr; p = p->ai_next)
    {
        char ipstr[INET6_ADDRSTRLEN] = {};
        if (p->ai_family == AF_INET)
        {
            auto *ipv4 = reinterpret_cast<sockaddr_in *>(p->ai_addr);
            addr = &(ipv4->sin_addr);
        } else if (p->ai_family == AF_INET6)
        {
            auto *ipv6 = reinterpret_cast<sockaddr_in6 *>(p->ai_addr);
            addr = &(ipv6->sin6_addr);
        }
        inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));
        GLog::log() << "SSH Host: " << host << "; IP: " << ipstr << std::endl;
    }

    if (addr == nullptr)
    {
        GLog::log(GLog::LogLevelError) << "Unable to get IP address of AF_INET6" << std::endl;
        this->close();
        return std::make_tuple(-1, "Unable to get IP address of AF_INET6", "", "");
    }

    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    sin.sin_addr = *static_cast<in_addr *>(addr);
    if (connect(sock, reinterpret_cast<sockaddr *>(&sin), sizeof(sin)) != 0)
    {
        GLog::log(GLog::LogLevelError) << "Could not connect to host!" << std::endl;
        this->close();
        return std::make_tuple(-1, "Could not connect to host!", "", "");
    }

    session = libssh2_session_init();
    if (!session)
    {
        GLog::log(GLog::LogLevelError) << "Could not initialize SSH session!\n" << std::endl;
        this->close();
        return std::make_tuple(-1, "Could not initialize SSH session!", "", "");
    }

    if (libssh2_session_handshake(session, sock))
    {
        fprintf(stderr, "Failure establishing SSH session\n");
        this->close();
        return std::make_tuple(-1, "Failure establishing SSH session\n", "", "");
    }

    if (libssh2_userauth_password(session, user.c_str(), password.c_str()))
    {
        fprintf(stderr, "Authentication failed!\n");
        this->close();
        return std::make_tuple(-1, "Authentication failed!", "", "");
    }


    channel = libssh2_channel_open_session(session);
    if (!channel)
    {
        GLog::log(GLog::LogLevelError) << "Unable to open channel\n" << std::endl;
        this->close();
        return std::make_tuple(-1, "Unable to open channel\n", "", "");
    }


    const auto [c, msg, ipv4, ipv6] = this->readRemoteIpv46();
    // return code 0: ALL, 1:ipv4, 2:ipv6
    return std::make_tuple(c, msg, ipv4, ipv6);
}


std::tuple<int32_t, std::string, std::string, std::string> SSHOpenWRTGetIp::readRemoteIpv46()
{
    if (libssh2_channel_exec(channel, command.c_str()))
    {
        this->close();
        return std::make_tuple(-1, "Unable to execute command\n", "", "");
    }

    std::string result;
    ssize_t rc;

    do
    {
        char buffer[4096];
        rc = libssh2_channel_read(channel, buffer, sizeof(buffer));
        if (rc > 0)
        {
            result.append(buffer, rc);
        }
    } while (rc > 0);

    GLog::log() << result << std::endl;


    const auto [c6, ipv6] = this->getIpv6(result);
    const auto [c4, ipv4] = this->getIpv4(result);
    // return code 0: ALL, 1:ipv4, 2:ipv6
    if (c6 == 0 && c4 == 0)
    {
        return std::make_tuple(0, "", ipv4, ipv6);
    }
    if (c4 == 0)
    {
        return std::make_tuple(1, "", ipv4, ipv6);
    }
    if (c6 == 0)
    {
        return std::make_tuple(2, "", ipv4, ipv6);
    }
    return std::make_tuple(-1, "SSHOpenWRT: Unknown error", ipv4, ipv6);
}

std::tuple<int32_t, std::string> SSHOpenWRTGetIp::getIpv4(const std::string &cmdResult) const
{
    auto pos = cmdResult.find(interfaceName);
    if (pos == std::string::npos)
    {
        GLog::log(GLog::LogLevelError) << "Host not found" << std::endl;
        return std::make_tuple(-1, "Host not found");
    }

    auto subStr = cmdResult.substr(pos, cmdResult.size());
    pos = subStr.find("inet");
    const auto endPos = subStr.find("peer");
    if (pos == std::string::npos || endPos == std::string::npos)
    {
        GLog::log(GLog::LogLevelError) << "Host not found" << std::endl;
        return std::make_tuple(-1, "Host not found");
    }
    pos += 5;

    auto ipv6 = subStr.substr(pos, endPos - pos - 1);
    return std::make_tuple(0, ipv6);
}

std::tuple<int32_t, std::string> SSHOpenWRTGetIp::getIpv6(const std::string &cmdResult) const
{
    auto pos = cmdResult.find(interfaceName);
    if (pos == std::string::npos)
    {
        GLog::log(GLog::LogLevelError) << "Host not found" << std::endl;
        return std::make_tuple(-1, "Host not found");
    }

    auto subStr = cmdResult.substr(pos, cmdResult.size());
    pos = subStr.find("inet6");

    if (pos == std::string::npos)
    {
        GLog::log(GLog::LogLevelError) << "Host not found" << std::endl;
        return std::make_tuple(-1, "Host not found");
    }
    pos += 6;

    subStr = subStr.substr(pos, subStr.size());
    const auto endPos = subStr.find('/');
    if (endPos == std::string::npos)
    {
        GLog::log(GLog::LogLevelError) << "Host not found" << std::endl;
        return std::make_tuple(-1, "Host not found");
    }
    const auto ipv6 = subStr.substr(0, endPos);

    return std::make_tuple(0, ipv6);
}

void SSHOpenWRTGetIp::close()
{
    if (channel != nullptr)
    {
        libssh2_channel_close(channel);
        libssh2_channel_free(channel);
        channel = nullptr;
    }

    if (session != nullptr)
    {
        libssh2_session_disconnect(session, "Normal Shutdown");
        libssh2_session_free(session);
        session = nullptr;
    }

    if (sock != INVALID_SOCKET)
    {
        closesocket(sock);
        sock = INVALID_SOCKET;
    }

    if (res) {
        freeaddrinfo(res);
        res = nullptr;
    }

    libssh2_exit();

    WSACleanup();
}

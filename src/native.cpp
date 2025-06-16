#include <memory>
#include "../include/SSHOpenWRTGetIp.h"
#include "../include/nlohmann/json.hpp"

const char* getIpv46ByOpenWRT_SSH(const std::string &host,
                                  const std::string &user,
                                  const std::string &password,
                                  const int32_t port,
                                  const std::string &interfaceName = "pppoe-wan")
{
    const auto sshOpenWRTGetIp = std::make_unique<SSHOpenWRTGetIp>(host, user, password, port, interfaceName);
    const auto [code , msg, ipv4, ipv6] = sshOpenWRTGetIp->execRemoteCommand();
    nlohmann::json json{};
    json["code"] = code;
    json["msg"] = msg;
    json["ipv4"] = ipv4;
    json["ipv6"] = ipv6;
    const auto cStr = json.dump().c_str();
    const auto alloc = static_cast<char *>(CoTaskMemAlloc(strlen(cStr) + 1));
    strcpy_s(alloc,strlen(cStr) + 1, cStr);
    return alloc;
}




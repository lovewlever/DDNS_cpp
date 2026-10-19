//
// Created by catog on 2025/6/11.
//

#include "GetTheLocalIP.h"

#include <algorithm>
#include <string>
#ifdef WIN32
#include <iphlpapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#elifdef __linux__
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#endif
#include <sstream>
#include <vector>

#include "GLog.h"
#include <array>

constexpr auto AddrTypeStrDhcp = "Dhcp";
constexpr auto AddrTypeStrTemporary = "Temporary";
constexpr auto AddrTypeStrPublic = "Public";
constexpr auto AddrTypeStrOther = "Other";
constexpr auto AddrTypeStrUnknown = "Unknown";

GetTheLocalIP::GetTheLocalIP() {}

GetTheLocalIP::~GetTheLocalIP() {}

#ifdef WIN32
// 将 IPv6 地址转换为字符串
std::string Ip6ToString(const IN6_ADDR &addr) {
  char str[INET6_ADDRSTRLEN] = {0};
  if (inet_ntop(AF_INET6, &addr, str, INET6_ADDRSTRLEN) == nullptr) {
    return "无效地址";
  }
  return std::string(str);
}

// 判断地址类型
std::string GetAddressType(DWORD dadState, bool isLinkLocal,
                           PIP_ADAPTER_UNICAST_ADDRESS addrInfo) {
  if (isLinkLocal) {
    return AddrTypeStrOther; // 链路本地地址 (fe80::/10)
  }
  if (dadState == IpDadStatePreferred) {
    if (addrInfo->PrefixOrigin == IpPrefixOriginDhcp) {
      return AddrTypeStrDhcp; // DHCPv6 分配的地址
    }
    if (addrInfo->SuffixOrigin == IpSuffixOriginRandom) {
      return AddrTypeStrTemporary; // 临时地址，通常由 SLAAC 生成用于隐私
    }
    if (addrInfo->PrefixOrigin == IpPrefixOriginRouterAdvertisement) {
      return AddrTypeStrPublic; // 公共地址，通常由 SLAAC 生成
    }
  }
  return AddrTypeStrUnknown; // 无法识别的地址类型
}

// 判断是否为以太网接口
bool IsEthernetAdapter(const PIP_ADAPTER_ADDRESSES adapter) {
  // 优先通过 FriendlyName 匹配“以太网”或“Ethernet”
  const std::wstring friendlyName(adapter->FriendlyName ? adapter->FriendlyName
                                                        : L"");
  std::wstring lowerName = friendlyName;
  std::ranges::transform(lowerName, lowerName.begin(), ::towlower);
  if (lowerName.find(L"以太网") !=
      std::wstring::
          npos /* || lowerName.find(L"ethernet") != std::wstring::npos*/) {
    return true;
  }
  // 备选：通过接口类型判断（IF_TYPE_ETHERNET_CSMACD = 6）
  if (adapter->IfType == IF_TYPE_ETHERNET_CSMACD) {
    return true;
  }
  return false;
}

#endif

std::string GetTheLocalIP::getLocalIp6() {

#ifdef WIN32
  // 初始化 Winsock
  WSADATA wsaData;
  if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
    GLog::log(GLog::LogLevelError)
        << "WSAStartup 失败: " << WSAGetLastError() << std::endl;
    return "1";
  }

  // 获取网卡信息
  ULONG bufferSize = 0;
  DWORD result = GetAdaptersAddresses(AF_INET6, GAA_FLAG_INCLUDE_PREFIX, NULL,
                                      NULL, &bufferSize);
  if (result != ERROR_BUFFER_OVERFLOW) {
    GLog::log(GLog::LogLevelError)
        << "GetAdaptersAddresses (查询缓冲区大小) 失败: " << result
        << std::endl;
    WSACleanup();
    return "1";
  }

  std::vector<char> buffer(bufferSize);
  PIP_ADAPTER_ADDRESSES adapters =
      reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
  result = GetAdaptersAddresses(AF_INET6, GAA_FLAG_INCLUDE_PREFIX, NULL,
                                adapters, &bufferSize);
  if (result != ERROR_SUCCESS) {
    GLog::log(GLog::LogLevelError)
        << "GetAdaptersAddresses 失败: " << result << std::endl;
    WSACleanup();
    return "1";
  }

  std::string finalIpv6Addr{};
  std::vector<IPV6XX> ipv6xxVec{};
  // 遍历网卡
  bool foundInterface = false;
  for (PIP_ADAPTER_ADDRESSES adapter = adapters; adapter != nullptr;
       adapter = adapter->Next) {
    if (IsEthernetAdapter(adapter)) {
      foundInterface = true;
      // printf("接口 %u: %ls\n", adapter->IfIndex, adapter->FriendlyName);
      for (PIP_ADAPTER_UNICAST_ADDRESS addr = adapter->FirstUnicastAddress;
           addr != nullptr; addr = addr->Next) {
        if (addr->Address.lpSockaddr->sa_family == AF_INET6) {
          const auto sockaddr =
              reinterpret_cast<SOCKADDR_IN6 *>(addr->Address.lpSockaddr);
          IN6_ADDR ip6Addr = sockaddr->sin6_addr;
          const bool isLinkLocal = IN6_IS_ADDR_LINKLOCAL(&ip6Addr);
          std::string addrType =
              GetAddressType(addr->DadState, isLinkLocal, addr);
          std::string ipv6String = Ip6ToString(ip6Addr);
          // printf("地址: %s, 类型: %s, DAD 状态: %d\n", ipv6String.c_str(),
          // addrType.c_str(), addr->DadState); 过滤
          if (addrType == AddrTypeStrDhcp || addrType == AddrTypeStrPublic) {
            IPV6XX ipv6xx{};
            ipv6xx.ip = ipv6String;
            ipv6xx.type = addrType;
            ipv6xxVec.push_back(ipv6xx);
          }
        }
      }
    }
  }

  std::ostringstream out{};

  for (const auto [type, ip] : ipv6xxVec) {
    out << ip << "-" << type << "-" << "\n";
  }
  // printf("final List: \n%s", out.str().c_str());

  // 过滤 DHCP的   没有使用Public的
  if (const auto it = std::ranges::find_if(
          ipv6xxVec, [](auto &ixx) { return ixx.type == AddrTypeStrDhcp; });
      it != ipv6xxVec.end()) {
    finalIpv6Addr = it->ip;
  } else if (const auto sb = std::ranges::find_if(
                 ipv6xxVec,
                 [](auto &ixx) { return ixx.type == AddrTypeStrPublic; });
             sb != ipv6xxVec.end()) {
    finalIpv6Addr = sb->ip;
  }

  if (!foundInterface) {
    GLog::log(GLog::LogLevelError) << "未找到接口 26" << std::endl;
  }

  WSACleanup();
  GLog::log() << "Find Machine Ipv6: " << finalIpv6Addr << std::endl;
  return finalIpv6Addr;
#elifdef __linux__

  std::vector<Ipv6XX> ip_list;
  struct ifaddrs *ifaddr{nullptr};

  if (getifaddrs(&ifaddr) == -1) {
    GLog::log(GLog::LogLevelError) << "Find Machine Ipv6: " << "fail!" << std::endl;
    return {};
  }

  for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) {
            continue;
        }

        // 检查网卡是否处于运行激活状态 (UP)
        if (!(ifa->ifa_flags & IFF_UP)) {
            continue;
        }

        // 过滤回环接口 (lo)
        if (std::string{ifa->ifa_name} == "lo") {
            continue;
        }

        int family = ifa->ifa_addr->sa_family;

        // 处理 IPv4
        /* if (family == AF_INET) {
            char ip_str[INET_ADDRSTRLEN];
            auto* sa = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr);
            if (inet_ntop(AF_INET, &(sa->sin_addr), ip_str, INET_ADDRSTRLEN)) {
                ip_list.push_back({ifa->ifa_name, std::string(ip_str)});
            }
        }
        // 处理 IPv6（如不需要可注释此分支）
        else  */if (family == AF_INET6) {
            char ip_str[INET6_ADDRSTRLEN];
            auto* sa6 = reinterpret_cast<struct sockaddr_in6*>(ifa->ifa_addr);
            if (inet_ntop(AF_INET6, &(sa6->sin6_addr), ip_str, INET6_ADDRSTRLEN)) {
                ip_list.push_back({ifa->ifa_name, std::string(ip_str)});
            }
        }
    }

    freeifaddrs(ifaddr);
    if (ip_list.empty()) {
      return {};
    } else {
      return ip_list[0].ip;
    }
    
#endif


  return {};
}

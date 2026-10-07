//
// Created by catog on 2025/6/11.
//

#include "NetworkRequest.h"
#include <chrono>
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"
#include <iostream>
#include <iterator>
#include <regex>
#include <string>
#ifdef __linux__
#include <sys/utsname.h>
#endif

#include "GLog.h"

const std::regex NetworkRequest::ipv4Regex{R"(\b(?:\d{1,3}\.){3}\d{1,3}\b)"};
const std::regex NetworkRequest::ipv6Regex{
    R"(^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(:[0-9a-fA-F]{1,4}){1,6}|:((:[0-9a-fA-F]{1,4}){1,7}|:))$)",
    std::regex::ECMAScript};
const std::regex NetworkRequest::ipv6RegexTq{
    R"((([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,6}:([0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}:([0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,4}:([0-9a-fA-F]{1,4}:){0,3}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,3}:([0-9a-fA-F]{1,4}:){0,2}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,2}:([0-9a-fA-F]{1,4}:){0,1}[0-9a-fA-F]{1,4}|[0-9a-fA-F]{1,4}::([0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}|::([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}|::))",
    std::regex::ECMAScript};

std::unique_ptr<httplib::SSLClient>
NetworkRequest::getClient(const std::string &url) const {
  auto domain = url;
  if (url.starts_with("https://")) {
    domain = regex_replace(url, std::regex{"https://"}, "");
  } else if (url.starts_with("http://")) {
    domain = regex_replace(url, std::regex{"http://"}, "");
  }
  if (const auto f = domain.rfind('/'); f != std::string::npos) {
    domain = domain.substr(0, f);
  }
  auto cli = std::make_unique<httplib::SSLClient>(domain, 443);
  // WSL下需要设置代理
#ifdef __linux__
  utsname buff{};
  if (uname(&buff) == 0) {
    std::string rel{buff.release};
    GLog::log() << "utsname release: " << rel << "\n";
    // 转为小写以兼容不同大小写情况 (如 Microsoft 或 WSL)
    std::transform(rel.begin(), rel.end(), rel.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    if (rel.find("microsoft") != std::string::npos ||
        rel.find("wsl") != std::string::npos) {
      cli->set_proxy("127.0.0.1", 7892);
    }
  }
#endif
  cli->set_connection_timeout(std::chrono::seconds(10));
  cli->set_read_timeout(std::chrono::seconds(10));
  cli->set_write_timeout(std::chrono::seconds(10));
  return cli;
}

NetworkRequest &NetworkRequest::getInstance() {
  static NetworkRequest instance;
  return instance;
}

std::string NetworkRequest::getNetworkIpv4(const std::string &url) const {
  GLog::log() << "Request Network Find Ipv4 Work..." << std::endl;
  const auto cli = getClient(url);
  const auto resp = cli->Get("/");
  if (resp.error() == httplib::Error::Success) {
    auto body = resp->body;
    std::smatch finalIpv4{};
    const auto b = std::regex_search(body, finalIpv4, ipv4Regex);
    if (b) {
      GLog::log() << "Request Network Find Ipv4 Url: " << url
                  << "; \n - Resp: " << body
                  << ";\n - Ipv4: " << finalIpv4[0].str() << ";\n"
                  << std::endl;
      return finalIpv4[0].str();
    }
    GLog::log() << "No IPv4 address was matched in the request result"
                << std::endl;
    return "";
  } else {
    GLog::log(GLog::LogLevelError) << "Request Network Find Ipv4 Url: " << url
                                   << "; Resp: " << resp.error() << std::endl;
  }
  return "";
}

std::string NetworkRequest::getNetworkIpv6(const std::string &url) const {
  GLog::log() << "Request Network Find Ipv6 Work..." << std::endl;
  const auto cli = getClient(url);
  if (const auto resp = cli->Get("/");
      resp.error() == httplib::Error::Success) {
    const std::string body = resp->body;
    std::smatch finalIpv6{};
    const auto b = std::regex_search(body, finalIpv6, ipv6RegexTq);
    if (b) {
      GLog::log() << "Request Network Find Ipv6 Url: " << url
                  << "; \n - Resp: " << body
                  << ";\n - Ipv6: " << finalIpv6[0].str() << "; \n"
                  << std::endl;
      return finalIpv6[0].str();
    }
    GLog::log() << "No IPv6 address was matched in the request result"
                << std::endl;
    return "";
  } else {
    GLog::log(GLog::LogLevelError) << "Request Network Find Ipv6 Url: " << url
                                   << "; Resp: " << resp.error() << std::endl;
  }
  return "";
}

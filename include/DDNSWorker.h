//
// Created by catog on 2025/6/12.
//

#ifndef DDNSWORKER_H
#define DDNSWORKER_H
#include <thread>

#include "YamlConfig.h"

class DDNSWorker {
public:
    DDNSWorker();
    ~DDNSWorker();

    int32_t readConfig();

    void run() const;

private:
    void distributionType(const YamlConfig::IpvConfig & ipvConf) const;

    void distributionProvider(const int32_t ipvInt, const YamlConfig::IpvConfig & ipvConf) const;

    void execIpv4Network(const YamlConfig::IpvConfig & ipvConf) const;
    void execIpv4SSHOpenWRT(const YamlConfig::IpvConfig & ipvConf) const;
    // void execIpv4Machine(const YamlConfig::IpvConfig & ipvConf) const;

    void execIpv6SSHOpenWRT(const YamlConfig::IpvConfig & ipvConf) const;
    void execIpv6Network(const YamlConfig::IpvConfig & ipvConf) const;
    void execIpv6Machine(const YamlConfig::IpvConfig & ipvConf) const;

};

#endif //DDNSWORKER_H

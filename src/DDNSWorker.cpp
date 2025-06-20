//
// Created by catog on 2025/6/12.
//

#include "DDNSWorker.h"

#include <iostream>
#include <ostream>
#include "YamlConfig.h"

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "AliCloudReport.h"
#include "GetTheLocalIP.h"
#include "httplib.h"
#include "NetworkRequest.h"
#include "SSHOpenWRTGetIp.h"
#include "GLog.h"

DDNSWorker::DDNSWorker()
= default;

DDNSWorker::~DDNSWorker()
= default;

int32_t DDNSWorker::readConfig()
{
    return YamlConfig::getInstance().loadConfig();
}

[[noreturn]] void DDNSWorker::run() const
{
    int32_t count{0};
    const auto &yamlConfig = YamlConfig::getInstance();
    const auto &ipvs = yamlConfig.getIpvConfigs();
    const auto &delayTime = yamlConfig.getDelayTimestamp();
    if (ipvs.size() == 0)
    {
        GLog::log(GLog::LogLevelError) << "No IPvs found" << std::endl;
        std::cerr << "No IPvs found" << std::endl;
        return;
    }
    GLog::log() << "DDNSWorker::run()====>>>>" << std::endl;
    GLog::log() << "log write log/*.log" << std::endl;

    std::cout << "DDNSWorker::run()====>>>>" << std::endl;
    std::cout << "log write log/*.log" << std::endl;

    while (true)
    {

        std::cout << std::flush;
        GLog::log() << "<<<<========================================================================>>>>" << std::endl;
        count++;
        for (const auto &ipv: ipvs)
        {
            if (ipv.Enable == YamlConfig::IpvConfEnableTrue)
            {
                GLog::log() << "==== Starting DDNS worker... ====" << std::endl;
                this->distributionType(ipv);
                GLog::log() << "==== Ending DDNS worker...   ====" << std::endl;
            } else
            {
                GLog::log(GLog::LogLevelError) << ipv.Subdomain << "." << ipv.Domain << " is disabled;" << std::endl;
            }
        }
        GLog::log() << "==== " << count << " times run" << std::endl;
        GLog::log() << "==== " << AliCloudReport::getUtcPlusEightTime() << " ====" << std::endl;
        GLog::log() << std::endl;
        GLog::log() << "Waiting delayTime: " << (delayTime * 0.01666666 * 0.001) << "min..." << std::endl;
        std::this_thread::sleep_for(std::chrono::milliseconds(delayTime));
        GLog::log() << "<<<<========================================================================>>>>" << std::endl;
        GLog::log() << std::endl;
        GLog::log() << std::endl;
    }
}

void DDNSWorker::distributionType(const YamlConfig::IpvConfig &ipvConf) const
{
    GLog::log() << "Worker Type: " << ipvConf.Type << std::endl;
    if (ipvConf.Type == YamlConfig::IpvConfTypeIpv4)
    {
        this->distributionProvider(4, ipvConf);
    } else if (ipvConf.Type == YamlConfig::IpvConfTypeIpv6)
    {
        this->distributionProvider(6, ipvConf);
    } else
    {
        GLog::log(GLog::LogLevelError) << "Invalid Type, Type must be IPV4 or IPV6" << std::endl;
    }
}

void DDNSWorker::distributionProvider(const int32_t ipvInt, const YamlConfig::IpvConfig &ipv) const
{
    GLog::log() << "Worker Provider: " << ipv.Provider << std::endl;
    if (ipv.Provider == YamlConfig::IpvConfProviderNetwork)
    {
        if (ipvInt == 4)
        {
            this->execIpv4Network(ipv);
        } else
        {
            this->execIpv6Network(ipv);
        }
    } else if (ipv.Provider == YamlConfig::IpvConfProviderSSHOpenWRT)
    {
        if (ipvInt == 4)
        {
            this->execIpv4SSHOpenWRT(ipv);
        } else
        {
            this->execIpv6SSHOpenWRT(ipv);
        }
    } else if (ipv.Provider == YamlConfig::IpvConfProviderMachine)
    {
        if (ipvInt == 4)
        {
            GLog::log(GLog::LogLevelError) << ipv.Provider << " only support windows ipv6" << std::endl;
        } else
        {
            this->execIpv6Machine(ipv);
        }
    } else
    {
        GLog::log(GLog::LogLevelError) << "Invalid Provider, Provider must be: SSH_OPENWRT or NETWORK or MACHINE" <<
                std::endl;
    }
}

void DDNSWorker::execIpv4Network(const YamlConfig::IpvConfig &ipvConf) const
{
    GLog::log() << "Worker Ipv4Network: ..." << std::endl;
    if (ipvConf.NetworkConfig.empty())
    {
        GLog::log(GLog::LogLevelError) << "No IPv4 network configuration" << std::endl;
        return;
    }
    std::string ipGet{};
    for (const auto &ipv: ipvConf.NetworkConfig)
    {
        const auto ip = NetworkRequest::getInstance().getNetworkIpv4(ipv);
        if (ip != "")
        {
            ipGet = ip;
            break;
        }
    }
    if (!ipGet.empty())
    {
        const auto report = ICloudReport::create(ipvConf.Cloud);
        if (report != nullptr)
        {
            const auto [AccessKeyId, AccessKeySecret] = YamlConfig::getInstance().getAliKeyConfig();
            report->addOrUpdateDomain(AccessKeyId, AccessKeySecret, ipvConf.Subdomain,
                                      ipvConf.Domain, ipGet, "A", ipvConf.TTL);
        } else
        {
            GLog::log(GLog::LogLevelError) << "Currently only supports Ali Cloud: [ALICLOUD]" << std::endl;
        }
    } else
    {
        GLog::log(GLog::LogLevelError) << "No ip was obtained" << std::endl;
    }
}

void DDNSWorker::execIpv4SSHOpenWRT(const YamlConfig::IpvConfig &ipvConf) const
{
    GLog::log() << "Worker Ipv4SSHOpenWRT: ..." << std::endl;
    const auto &sshConfig = ipvConf.SSHConfig;
    if (sshConfig.host.empty() || sshConfig.user.empty() || sshConfig.password.empty() ||
        sshConfig.InterfaceName.empty())
    {
        GLog::log(GLog::LogLevelError) << "No IPv4 SSHOpenWRT configuration" << std::endl;
        return;
    }
    SSHOpenWRTGetIp sshOpenWRTGetIp{
        sshConfig.host, sshConfig.user, sshConfig.password, sshConfig.port, sshConfig.InterfaceName
    };
    const auto &[code, msg, ipv4, ipv6] = sshOpenWRTGetIp.execRemoteCommand();
    if (code == 0 || code == 1)
    {
        const auto report = ICloudReport::create(ipvConf.Cloud);
        if (report != nullptr)
        {
            const auto [AccessKeyId, AccessKeySecret] = YamlConfig::getInstance().getAliKeyConfig();
            report->addOrUpdateDomain(AccessKeyId, AccessKeySecret, ipvConf.Subdomain,
                                 ipvConf.Domain, ipv4, "A", ipvConf.TTL);
        } else
        {
            GLog::log(GLog::LogLevelError) << "Currently only supports Ali Cloud: [ALICLOUD]" << std::endl;
        }
    } else
    {
        GLog::log(GLog::LogLevelError) << "Failed to get IPv4 SSHOpenWRT: " << msg << std::endl;
    }
}

void DDNSWorker::execIpv6SSHOpenWRT(const YamlConfig::IpvConfig &ipvConf) const
{
    GLog::log() << "Worker Ipv6SSHOpenWRT: ..." << std::endl;
    const auto &sshConfig = ipvConf.SSHConfig;
    if (sshConfig.host.empty() || sshConfig.user.empty() || sshConfig.password.empty() ||
        sshConfig.InterfaceName.empty())
    {
        GLog::log(GLog::LogLevelError) << "No IPv6 SSHOpenWRT configuration" << std::endl;
        return;
    }
    SSHOpenWRTGetIp sshOpenWRTGetIp{
        sshConfig.host, sshConfig.user, sshConfig.password, sshConfig.port, sshConfig.InterfaceName
    };
    const auto &[code, msg, ipv4, ipv6] = sshOpenWRTGetIp.execRemoteCommand();
    if (code == 0 || code == 1)
    {
        const auto report = ICloudReport::create(ipvConf.Cloud);
        if (report != nullptr)
        {
            const auto [AccessKeyId, AccessKeySecret] = YamlConfig::getInstance().getAliKeyConfig();
            report->addOrUpdateDomain(AccessKeyId, AccessKeySecret, ipvConf.Subdomain,
                                 ipvConf.Domain, ipv6, "AAAA", ipvConf.TTL);
        } else
        {
            GLog::log(GLog::LogLevelError) << "Currently only supports Ali Cloud: [ALICLOUD]" << std::endl;
        }
    } else
    {
        GLog::log(GLog::LogLevelError) << "Failed to get IPv6 SSHOpenWRT: " << msg << std::endl;
    }
}

void DDNSWorker::execIpv6Network(const YamlConfig::IpvConfig &ipvConf) const
{
    GLog::log() << "Worker Ipv6Network: ..." << std::endl;
    if (ipvConf.NetworkConfig.empty())
    {
        GLog::log(GLog::LogLevelError) << "No IPv6 network configuration" << std::endl;
        return;
    }
    std::string ipGet{};
    for (const auto &ipv: ipvConf.NetworkConfig)
    {
        const auto ip = NetworkRequest::getInstance().getNetworkIpv6(ipv);
        if (ip != "")
        {
            ipGet = ip;
            break;
        }
    }
    if (!ipGet.empty())
    {
        const auto report = ICloudReport::create(ipvConf.Cloud);
        if (report != nullptr)
        {
            const auto [AccessKeyId, AccessKeySecret] = YamlConfig::getInstance().getAliKeyConfig();
            report->addOrUpdateDomain(AccessKeyId, AccessKeySecret, ipvConf.Subdomain, ipvConf.Domain, ipGet, "AAAA",
                                 ipvConf.TTL);
        } else
        {
            GLog::log(GLog::LogLevelError) << "Currently only supports Ali Cloud: [ALICLOUD]" << std::endl;
        }
    } else
    {
        GLog::log(GLog::LogLevelError) << "No ip was obtained" << std::endl;
    }
}

void DDNSWorker::execIpv6Machine(const YamlConfig::IpvConfig &ipvConf) const
{
    GLog::log() << "Worker Ipv6Machine: ..." << std::endl;
    GetTheLocalIP getTheLocalIP{};
    const auto ipv6 = getTheLocalIP.getLocalIp6();
    if (!ipv6.empty())
    {
        const auto report = ICloudReport::create(ipvConf.Cloud);
        if (report != nullptr)
        {
            const auto [AccessKeyId, AccessKeySecret] = YamlConfig::getInstance().getAliKeyConfig();
            report->addOrUpdateDomain(AccessKeyId, AccessKeySecret,
                                 ipvConf.Subdomain, ipvConf.Domain, ipv6, "AAAA", ipvConf.TTL);
        } else
        {
            GLog::log(GLog::LogLevelError) << "Currently only supports Ali Cloud: [ALICLOUD]" << std::endl;
        }
    } else
    {
        GLog::log(GLog::LogLevelError) << "No ip was obtained" << std::endl;
    }
}

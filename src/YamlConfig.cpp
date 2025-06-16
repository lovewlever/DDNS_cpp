//
// Created by catog on 2025/6/11.
//

#include "YamlConfig.h"

#include <iostream>
#include "GLog.h"

const std::string YamlConfig::IpvConfTypeIpv4{"IPV4"};
const std::string YamlConfig::IpvConfTypeIpv6{"IPV6"};

const std::string YamlConfig::IpvConfProviderSSHOpenWRT{"SSH_OPENWRT"};
const std::string YamlConfig::IpvConfProviderNetwork{"NETWORK"};
const std::string YamlConfig::IpvConfProviderMachine{"MACHINE"};
const std::string YamlConfig::IpvConfCloudAliCloud{"ALICLOUD"};

const std::string YamlConfig::IpvConfEnableTrue{"TRUE"};
const std::string YamlConfig::IpvConfEnableFalse{"FALSE"};



YamlConfig::YamlConfig(): config{std::make_unique<Config>()}
{
}

YamlConfig &YamlConfig::getInstance()
{
    static YamlConfig instance;
    return instance;
}

int YamlConfig::loadConfig() const
{
    GLog::log() << "loadConfig..." << std::endl;
    const auto yaml = YAML::LoadFile("config/config.yaml");
    if (yaml.IsNull())
    {
        std::cerr << "YAML::LoadFile failed!" << std::endl;
        return -1;
    }

    try
    {
        AliKeyConfig alikeyConfig{};
        // AliKeyConfig
        const auto akc = yaml["AliKeyConfig"];
        alikeyConfig.AccessKeyId = akc["AccessKeyId"].as<std::string>();
        alikeyConfig.AccessKeySecret = akc["AccessKeySecret"].as<std::string>();
        config->aliKeyConfig = alikeyConfig;

        // DelayTime
        config->delayTime = yaml["DelayTime"].as<int>();

        // IpvConfig
        const auto ipvConfigNode = yaml["IpvConfig"];
        std::vector<IpvConfig> ipvConfigs{};
        for (const auto &node: ipvConfigNode)
        {
            IpvConfig ic{};
            ic.Type = node["Type"].as<std::string>();
            ic.Domain = node["Domain"].as<std::string>();
            ic.Subdomain = node["Subdomain"].as<std::string>();
            ic.Provider = node["Provider"].as<std::string>();
            ic.Cloud = node["Cloud"].as<std::string>();
            ic.TTL = node["TTL"].as<std::string>();
            ic.Enable = node["Enable"].as<std::string>();
            // SSHConfig
            if (node["SSHConfig"])
            {
                SSHConfig sshConfig{};
                const auto sshNode = node["SSHConfig"];
                sshConfig.host = sshNode["Host"].as<std::string>();
                sshConfig.port = sshNode["Port"].as<int>();
                sshConfig.user = sshNode["User"].as<std::string>();
                sshConfig.password = sshNode["Password"].as<std::string>();
                sshConfig.InterfaceName = sshNode["InterfaceName"].as<std::string>();
                ic.SSHConfig = sshConfig;
            }

            // NetworkConfig
            if (node["NetworkConfig"])
            {
                std::vector<std::string> networkUrls{};
                for (const auto netConfigNode = node["NetworkConfig"]; const auto ncNode: netConfigNode)
                {
                    networkUrls.push_back(ncNode.as<std::string>());
                }
                ic.NetworkConfig = networkUrls;
            }
            ipvConfigs.push_back(ic);
        }
        config->ipvConfigs = ipvConfigs;
    } catch (const std::exception &e)
    {
        GLog::log(GLog::LogLevelError) << e.what() << std::endl;
        return -1;
    }

    return 0;
}

const YamlConfig::AliKeyConfig &YamlConfig::getAliKeyConfig() const
{
    return config->aliKeyConfig;
}

int32_t YamlConfig::getDelayTimestamp() const
{
    return config->delayTime * 60 * 1000;
}

const std::vector<YamlConfig::IpvConfig> &YamlConfig::getIpvConfigs() const
{
    return config->ipvConfigs;
}

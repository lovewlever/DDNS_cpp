#ifndef YAMLCONFIG_H
#define YAMLCONFIG_H
#include <yaml-cpp/yaml.h>

class YamlConfig
{
public:
    static const std::string IpvConfTypeIpv4;
    static const std::string IpvConfTypeIpv6;

    static const std::string IpvConfProviderSSHOpenWRT;
    static const std::string IpvConfProviderNetwork;
    static const std::string IpvConfProviderMachine;

    static const std::string IpvConfCloudAliCloud;

    static const std::string IpvConfEnableTrue;
    static const std::string IpvConfEnableFalse;
public:
    struct SSHConfig
    {
        std::string host{};
        int32_t port{22};
        std::string user{};
        std::string password{};
        std::string InterfaceName{};
    };

    struct AliKeyConfig
    {
        std::string AccessKeyId{};
        std::string AccessKeySecret{};
    };

    struct IpvConfig
    {
        std::string Type{};
        std::string Domain{};
        std::string Subdomain{};
        std::string Provider{};
        std::string Cloud{};
        std::string Enable{};
        std::string TTL{};
        std::vector<std::string> NetworkConfig{};
        SSHConfig SSHConfig{};
    };

    struct Config
    {
        AliKeyConfig aliKeyConfig{};
        int32_t delayTime{10};
        std::vector<IpvConfig> ipvConfigs{};
    };

private:
    YamlConfig();

    std::unique_ptr<Config> config{nullptr};

public:
    ~YamlConfig() = default;

    static YamlConfig &getInstance();

    YamlConfig(const YamlConfig &) = delete;

    YamlConfig &operator=(const YamlConfig &) = delete;

    int loadConfig() const;

    const AliKeyConfig &getAliKeyConfig() const;
    int32_t getDelayTimestamp() const;
    const std::vector<IpvConfig> &getIpvConfigs() const;
};


#endif //YAMLCONFIG_H

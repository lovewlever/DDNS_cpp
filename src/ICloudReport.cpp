//
// Created by catog on 2025/6/16.
//

#include "../include/ICloudReport.h"

#include "../include/AliCloudReport.h"
#include "../include/YamlConfig.h"

std::unique_ptr<ICloudReport> ICloudReport::create(const std::string &cloud)
{
    if (cloud == YamlConfig::IpvConfCloudAliCloud)
    {
        return std::make_unique<AliCloudReport>();
    }
    return nullptr;
}

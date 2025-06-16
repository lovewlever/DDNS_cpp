//
// Created by catog on 2025/6/16.
//

#ifndef ICLOUDREPORT_H
#define ICLOUDREPORT_H

#include <iostream>

class ICloudReport
{
public:
    ICloudReport() = default;

    virtual ~ICloudReport() = default;

    virtual void addOrUpdateDomain(const std::string &accessKey,
                              const std::string &accessKeySecret,
                              const std::string &subDomain,
                              const std::string &domain,
                              const std::string &ip,
                              const std::string &type,
                              const std::string &ttl) const = 0;

    static std::unique_ptr<ICloudReport> create(const std::string &cloud);
};


#endif //ICLOUDREPORT_H

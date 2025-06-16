//
// Created by catog on 2025/6/12.
//

#ifndef ALICLOUDREPORT_H
#define ALICLOUDREPORT_H
#include <map>
#include <string>
#include "nlohmann/json.hpp"
#include "ICloudReport.h"


class AliCloudReport final : public ICloudReport
{
public:
    AliCloudReport() = default;

    ~AliCloudReport() override = default;

    std::string networkRequest(const std::string &accessKeySecret,
                               const std::string &action,
                               std::map<std::string, std::string> &params) const;

    nlohmann::json getRecordDomainIp(const std::string &accessKey,
                                  const std::string &accessKeySecret,
                                  const std::string &subDomain,
                                  const std::string &domain) const;

    void addOrUpdateDomain(const std::string &accessKey,
                              const std::string &accessKeySecret,
                              const std::string &subDomain,
                              const std::string &domain,
                              const std::string &ip,
                              const std::string &type,
                              const std::string &ttl) const override;

    static std::string getUtcTime();

    static std::string getUtcPlusEightTime();

    int64_t getTimestamp() const;

private:
    std::string generateSignature(const std::map<std::string, std::string> &params,
                                  const std::string &accessKeySecret) const;

    std::string base64Encode(const unsigned char *input, int length) const;

    std::string hmacSha1(const std::string &key, const std::string &data) const;


    std::string percentEncode(const std::string &value) const;

    int32_t addDomain(const std::string &accessKey,
                      const std::string &accessKeySecret,
                      const std::string &subDomain,
                      const std::string &domain,
                      const std::string &ip,
                      const std::string &type,
                      const std::string &ttl) const;

    int32_t updateDomain(
        const std::string &accessKey,
        const std::string &accessKeySecret,
        const std::string &subDomain,
        const std::string &domain,
        const std::string &ip,
        const std::string &type,
        const std::string &ttl,
        const std::string &recordId) const;
};


#endif //ALICLOUDREPORT_H

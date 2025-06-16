//
// Created by catog on 2025/6/12.
//

#include "AliCloudReport.h"
#define  CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>
#include <openssl/hmac.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include "nlohmann/json.hpp"
#include "GLog.h"

std::string AliCloudReport::networkRequest(
    const std::string &accessKeySecret,
    const std::string &action,
    std::map<std::string, std::string> &params) const
{
    std::this_thread::sleep_for(std::chrono::seconds(2));
    const std::string timestamp = getUtcTime();
    std::map<std::string, std::string> paramsVec{
        {"SignatureMethod", "HMAC-SHA1"},
        {"SignatureNonce", std::to_string(getTimestamp())},
        {"SignatureVersion", "1.0"},
        {"Timestamp", timestamp},
        {"Action", action},
        {"Format", "json"},
        {"Version", "2015-01-09"},
    };
    for (const auto &[fst, snd]: params)
    {
        paramsVec[fst] = snd;
    }

    std::string signature = generateSignature(paramsVec, accessKeySecret);

    paramsVec["Signature"] = signature;
    std::ostringstream url;
    url << "/?";
    for (auto it = paramsVec.begin(); it != paramsVec.end(); ++it)
    {
        if (it != paramsVec.begin()) url << "&";
        url << percentEncode(it->first) << "=" << percentEncode(it->second);
    }

    httplib::SSLClient cli("alidns.aliyuncs.com", 443);
    const auto res = cli.Get(url.str());

    // ERROR
    // {
    //"RequestId" : "AF63231B-E72A-5AA9-99B0-E0EFE76D4FE5",
    //"Message" : "Specified access key is not found.",
    //"Recommend" : "https://api.aliyun.com/troubleshoot?q=InvalidAccessKeyId.NotFound&product=Alidns&requestId=AF63231B-E72A-5AA9-99B0-E0EFE76D4FE5",
    //"HostId" : "alidns.aliyuncs.com",
    //"Code" : "InvalidAccessKeyId.NotFound"
    //}
    auto b = res->body;
    if (res && res->status == 200)
    {
        return b;
    }
    try
    {
        const auto jsonObj = nlohmann::json::parse(b);
        GLog::log(GLog::LogLevelError) << "HTTP request failed: " << jsonObj["Message"].get<std::string>() << std::endl;
    } catch (const std::exception &e)
    {
        GLog::log() << "HTTP request failed: " << e.what() << std::endl;
    }
    return "";
}

constexpr int32_t GetRecordDomainIpCodeERROR = 0x01;
constexpr int32_t GetRecordDomainIpCodeAddDomain = 0x02;
constexpr int32_t GetRecordDomainIpCodeUpdateDomain = 0x03;

/**
 *
 * @param accessKey
 * @param accessKeySecret
 * @param subDomain
 * @param domain
 * @return
 *
* {
  "TotalCount" : 1,
  "PageSize" : 20,
  "RequestId" : "9953C05B-819D-5747-B1B4-531F7580C2E0",
  "DomainRecords" : {
    "Record" : [ {
      "Status" : "ENABLE",
      "Line" : "default",
      "RR" : "ddns6winserver",
      "Locked" : false,
      "Type" : "AAAA",
      "DomainName" : "dfordog.cn",
      "Value" : "2408:8215:5b20:9860:750b:2f3e:f405:665c",
      "RecordId" : "1932603865284210688",
      "TTL" : 600,
      "Weight" : 1
    } ]
  },
  "PageNumber" : 1
}
 */
nlohmann::json AliCloudReport::getRecordDomainIp(
    const std::string &accessKey,
    const std::string &accessKeySecret,
    const std::string &subDomain,
    const std::string &domain) const
{
    std::map<std::string, std::string> paramsVec{
        {"SubDomain", subDomain + "." + domain},
        {"AccessKeyId", accessKey},
    };

    const auto resp = this->networkRequest(accessKeySecret, "DescribeSubDomainRecords", paramsVec);
    try
    {
        const auto jsonObj = nlohmann::json::parse(resp);
        if (jsonObj["TotalCount"].get<int>() <= 0)
        {
            return {{"code", GetRecordDomainIpCodeAddDomain}};
        }
        auto domainObj = jsonObj["DomainRecords"]["Record"][0];
        domainObj["code"] = GetRecordDomainIpCodeUpdateDomain;
        return domainObj;
    } catch (const std::exception &e)
    {
        GLog::log(GLog::LogLevelError) << "JSON parsing failed when querying SubDomain: " << e.what() << std::endl;
        return {{"code", GetRecordDomainIpCodeERROR}};
    }
}

/**
 *
 * @param accessKey
 * @param accessKeySecret
 * @param subDomain
 * @param domain
 * @param ip
 * @param type
 * @param ttl
 *
* {
      "Status" : "ENABLE",
      "Line" : "default",
      "RR" : "ddns6winserver",
      "Locked" : false,
      "Type" : "AAAA",
      "DomainName" : "dfordog.cn",
      "Value" : "2408:8215:5b20:9860:750b:2f3e:f405:665c",
      "RecordId" : "1932603865284210688",
      "TTL" : 600,
      "Weight" : 1
    }
 */
void AliCloudReport::addOrUpdateDomain(const std::string &accessKey, const std::string &accessKeySecret,
                                       const std::string &subDomain, const std::string &domain,
                                       const std::string &ip, const std::string &type, const std::string &ttl) const
{
    GLog::log() << "Worker Add or Update SubDomain: " << subDomain << "." << domain << "..." << std::endl;
    const auto findResult = this->getRecordDomainIp(accessKey, accessKeySecret, subDomain, domain);
    if (findResult["code"] == GetRecordDomainIpCodeAddDomain)
    {
        GLog::log(GLog::LogLevelError) << "The cloud SubDomain may be empty, add this SubDomain: " << subDomain << "." << domain <<
                std::endl;
        const auto i = this->addDomain(accessKey, accessKeySecret, subDomain, domain, ip, type, ttl);
        if (i == 0)
        {
            GLog::log() << "Add " << subDomain << "." << domain << " successfully added" << std::endl;
            GLog::log() << "Enjoy~ " << std::endl;
        } else
        {
            GLog::log() << "Failed to add SubDomain: " << subDomain << "." << domain << std::endl;
        }
    } else if (findResult["code"] == GetRecordDomainIpCodeUpdateDomain)
    {
        const auto cloudIp = findResult["Value"].get<std::string>();
        const auto recordId = findResult["RecordId"].get<std::string>();
        if (cloudIp == ip)
        {
            GLog::log() << "The IP on the cloud is consistent with the IP to be updated, no update is required" <<
                    std::endl;
            return;
        }
        GLog::log() << "Update " << cloudIp << " to " << ip << " ..." << std::endl;
        const auto i = this->updateDomain(accessKey, accessKeySecret, subDomain, domain, ip, type, ttl, recordId);
        if (i == 0)
        {
            GLog::log() << "Update " << subDomain << "." << domain << " successfully" << std::endl;
            GLog::log() << "Enjoy~ " << std::endl;
        } else
        {
            GLog::log() << "Failed to update SubDomain: " << subDomain << "." << domain << std::endl;
        }
    }
}

/**
 *
 * @param accessKey
 * @param accessKeySecret
 * @param subDomain
 * @param domain
 * @param ip
 * @param type
 * @param ttl
 * @return
 * {
  "RequestId" : "99486677-1967-5F2D-8F4C-F07BE4C69229",
  "RecordId" : "1933362074172787712"
}
 */
int32_t AliCloudReport::addDomain(
    const std::string &accessKey,
    const std::string &accessKeySecret,
    const std::string &subDomain,
    const std::string &domain,
    const std::string &ip,
    const std::string &type,
    const std::string &ttl) const
{
    std::map<std::string, std::string> paramsVec{
        {"RR", subDomain},
        {"TTL", ttl},
        {"Type", type},
        {"Value", ip},
        {"AccessKeyId", accessKey},
        {"DomainName", domain},
    };
    const auto resp = this->networkRequest(accessKeySecret, "AddDomainRecord", paramsVec);
    try
    {
        const auto jsonObj = nlohmann::json::parse(resp);
        if (!jsonObj.empty())
        {
            return 0;
        }
        GLog::log(GLog::LogLevelError) <<
                "The cloud may not return data when adding SubDomain. Please check whether the addition is successful on the cloud."
                << std::endl;
        return -1;
    } catch (const std::exception &e)
    {
        GLog::log(GLog::LogLevelError) << "Add SubDomain failed: " << e.what() << std::endl;
        return -1;
    }
}

/**
 *
 * @param accessKey
 * @param accessKeySecret
 * @param subDomain
 * @param domain
 * @param ip
 * @param type
 * @param ttl
 * @param recordId
 * @return
 *
* {
  "RequestId" : "99486677-1967-5F2D-8F4C-F07BE4C69229",
  "RecordId" : "1933362074172787712"
}
 */
int32_t AliCloudReport::updateDomain(const std::string &accessKey,
                                     const std::string &accessKeySecret,
                                     const std::string &subDomain,
                                     const std::string &domain,
                                     const std::string &ip,
                                     const std::string &type,
                                     const std::string &ttl,
                                     const std::string &recordId) const
{
    std::map<std::string, std::string> paramsVec{
        {"RR", subDomain},
        {"TTL", ttl},
        {"Type", type},
        {"Value", ip},
        {"AccessKeyId", accessKey},
        {"DomainName", domain},
        {"RecordId", recordId},
    };
    const auto resp = this->networkRequest(accessKeySecret, "UpdateDomainRecord", paramsVec);
    try
    {
        const auto jsonObj = nlohmann::json::parse(resp);
        if (!jsonObj.empty())
        {
            return 0;
        }
        GLog::log(GLog::LogLevelError) <<
                "When updating SubDomain, the cloud may not return data. Please check whether the update is successful in the cloud."
                << std::endl;
        return -1;
    } catch (const std::exception &e)
    {
        GLog::log(GLog::LogLevelError) << "Update SubDomain failed: " << e.what() << std::endl;
        return -1;
    }
}


std::string AliCloudReport::percentEncode(const std::string &value) const
{
    std::ostringstream encoded;
    for (auto c: value)
    {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
        {
            encoded << c;
        } else
        {
            encoded << '%' << std::uppercase << std::hex << (int) (unsigned char) c;
        }
    }
    return encoded.str();
}

std::string AliCloudReport::generateSignature(const std::map<std::string, std::string> &params,
                                              const std::string &accessKeySecret) const
{
    // 1. 按照参数名称的字典顺序排序
    std::map<std::string, std::string> sortedParams = params;

    // 2. Canonicalized Query String
    std::ostringstream queryStream;
    for (auto it = sortedParams.begin(); it != sortedParams.end(); ++it)
    {
        if (it != sortedParams.begin()) queryStream << "&";
        queryStream << percentEncode(it->first) << "=" << percentEncode(it->second);
    }

    std::string canonicalizedQueryString = queryStream.str();

    // 3. StringToSign
    std::string stringToSign = "GET&%2F&" + percentEncode(canonicalizedQueryString);

    // 4. 生成签名
    std::string key = accessKeySecret + "&";
    std::string signature = hmacSha1(key, stringToSign);

    return signature;
}

std::string AliCloudReport::base64Encode(const unsigned char *input, int length) const
{
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, input, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    std::string result(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);

    return result;
}

std::string AliCloudReport::hmacSha1(const std::string &key, const std::string &data) const
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;

    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, key.c_str(), key.length(), EVP_sha1(), NULL);
    HMAC_Update(ctx, (unsigned char *) data.c_str(), data.length());
    HMAC_Final(ctx, digest, &digest_len);
    HMAC_CTX_free(ctx);

    return base64Encode(digest, digest_len);
}

std::string AliCloudReport::getUtcTime()
{
    const auto now = std::chrono::system_clock::now();
    const auto time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

std::string AliCloudReport::getUtcPlusEightTime()
{
    const auto now = std::chrono::system_clock::now() + std::chrono::hours(8);
    const auto time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time_t), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

int64_t AliCloudReport::getTimestamp() const
{
    const auto now = std::chrono::system_clock::now();
    const auto time_t = std::chrono::system_clock::to_time_t(now);
    return time_t;
}
